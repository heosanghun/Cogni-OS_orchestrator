# Trusted Runner 격리·증거 계약

## 신뢰 경계

Trusted Runner는 환경 변수 정리나 실행 후 `git diff`를 보안 경계로 간주하지 않는다.
검증 명령을 실행하기 전에 다음 조건을 모두 만족해야 한다.

1. Linux의 관리자 소유 `/usr/bin/bwrap`와 전체 상위 경로가 링크가 아니고 일반 사용자가 쓸 수 없어야 한다.
2. 외부 privileged broker가 커밋 스냅샷 전체를 root 소유·actor 쓰기 불가 상태로 넘겨야 한다.
3. 스냅샷은 `/workspace`에 읽기 전용, 전용 scratch는 `/sandbox`에만 쓰기 가능하게 바인드한다.
4. mount/PID/IPC/UTS/user/cgroup/network namespace를 분리하며, 네트워크 권한이 명시된 작업만 `--share-net`을 사용한다.
5. 검증 전후에 source commit, Git tree, 스냅샷 manifest, 실행 파일 SHA-256을 다시 확인한다.

root broker daemon/client/protocol과 설치 명세는 저장소에 구현되어 있다. 그러나
현재 Windows 호스트에는 배포할 수 없고, 별도 root Linux에서 immutable runtime,
키, 그룹, systemd 서비스 설치와 실제 integration gate를 통과했다는 증거도 아직
없다. 따라서 현재 production trusted validation은 의도적으로 `NO_GO`이며,
테스트용 direct adapter는 unit test 범위에서만 사용된다.

### 외부 broker 통합 계약

프로토콜은 `cogni-os-snapshot-fd-lease-v1`이다. runner는 고정된 root 소유 Unix socket `/run/cogni-os/trusted-snapshot-broker.sock`만 사용하고 peer UID 0을 검증한다. 비특권 runner가 고정 Git 정책으로 커밋을 검사하고 caller 소유의 읽기 전용 source tree를 먼저 만든다. runner는 이 봉인된 directory FD를 `SCM_RIGHTS`로 보내며, broker는 경로나 Git을 사용하지 않고 descriptor-relative bounded no-follow 복사만 수행해 root 소유 sibling tree `/run/cogni-os/trusted-snapshots`에 저장한다. broker는 execution binding과 nonce에 묶인 lease 및 `O_PATH` directory FD를 다시 `SCM_RIGHTS`로 넘긴다. runner는 pathname만 받은 응답을 거부한다. broker proof는 copy provenance와 cleanup만 증명하며 source commit/tree authenticity를 증명하지 않는다.

종료 시 runner는 `finally`에서 release lease를 시도할 뿐 직접 unlink/chmod하지 않는다. broker가 lease ID·device·inode·manifest·execution binding·receipt preimage를 다시 검증한 뒤 삭제하고 서명된 cleanup ack를 반환한다. 실제 root Linux integration test가 통과하기 전에는 절대 `GO`로 전환하지 않는다.

## Git 객체 스트리밍 한계

고정 OS Git만 사용하고 actor의 `PATH`, Git 설정, credential helper, proxy, SSH/Python 환경을 전달하지 않는다. Git 실행 파일은 실행 전후 SHA-256이 같아야 한다.

커밋 스냅샷은 archive가 아니라 정확한 `ls-tree`와 `cat-file --batch` 객체 바이트로 만든다. 모든 출력은 스트리밍으로 처리한다.

- 파일 수: 최대 50,000개
- 개별 경로: 최대 4,096바이트
- 전체 경로 바이트: 최대 32 MiB
- 개별 파일: 최대 64 MiB
- 전체 파일 바이트: 최대 512 MiB
- 일반 Git control 출력: 최대 4 MiB
- Git stderr 보관: 최대 64 KiB
- Git 검사 시간: 최대 15초

0바이트 파일이라도 항목 수에 포함한다. 0바이트 파일만 있는 작은 정상 스냅샷의 총 크기 0은 허용하지만 동일한 entry/path/file/total 한계를 적용한다. 한계를 넘으면 snapshot root를 만들거나 blob을 읽기 전에 실패한다. symlink, submodule, 특수 mode, 중복 경로, Unicode NFC/casefold 충돌, 잘린 NUL/header/body, object ID·type·size 불일치는 모두 `NO_GO`다. materialization policy는 `git-object-dirfd-nofollow-stream-v2`이다.

## 고정 관리자 런타임

검증 명령의 Python·Node·PowerShell은 actor 환경에서 검색하지 않는다. production Linux에서 허용되는 후보는 다음과 같다.

- Python: `/usr/bin/python3.12`, `/usr/bin/python3.10`
- Node: `/usr/bin/node`
- PowerShell: `/opt/microsoft/powershell/7/pwsh`

argv[0]은 위 절대 경로 중 하나와 정확히 같아야 한다. 실행 파일과 `/`까지의 모든 상위 경로는 root 소유, 링크 없음, group/world 쓰기 불가여야 한다. 영수증에는 policy ID, 종류, 절대 경로, SHA-256, `fixed-admin-path-chain` provenance를 기록한다. `COGNI_TRUSTED_*`, actor `PATH`, `sys.executable`, `shutil.which()`로 runtime을 바꾸는 동작은 production에서 허용하지 않는다.

Python은 `python -m pytest|unittest ...` 또는 `python committed_script.py ...` 두 형식만 허용한다. `--help`, `--version`, `-X`, `-S`를 포함한 interpreter 선행 옵션과 `-c`/stdin은 테스트를 실행하지 않고 exit 0으로 우회할 수 있으므로 거부한다. symlink alias와 `..`/dot-segment argv[0]도 resolved target이 같더라도 lexical canonical 경로가 아니면 거부한다.

PowerShell은 정확한 `-File` 형식만 허용한다. 약어, 별칭, `-Command`, `-EncodedCommand`, stdin, `--%`, splatting, 제어·메타 문자는 거부하며 실제 argv를 `-NoProfile -NonInteractive -File` 형식으로 다시 만든다.

## canonical 격리 argv와 영수증

격리 backend가 증명한 `system_roots`만 같은 경로에 읽기 전용 바인드한다. `/usr`와 ELF loader를 제공하는 `/lib`는 필수이며, 존재할 때만 `/opt`, `/lib64`, `/bin`, `/sbin`을 이 고정 순서로 추가한다. usr-merged symlink는 leaf가 root 소유이고 resolved target 전체가 root 소유·일반 사용자 쓰기 불가일 때만 허용한다. host의 임의 디렉터리를 다시 조사해 mount를 추가하지 않는다. `/workspace`와 `/sandbox` 바인드 순서, `--clearenv`, 정렬된 `--setenv`, 변환된 실행 argv가 canonical 값과 한 항목이라도 다르면 증거는 무효다.

Trusted receipt는 schema 3과 `cogni-os-trusted-runner-v3`를 사용한다. 다음 항목은 exact-schema로 검증한다.

- top-level receipt와 retained receipt
- isolation backend와 system roots
- validation receipt
- command policy와 executable binding
- code path와 커밋 스냅샷 SHA-256
- sandbox environment와 SHA-256
- 전체 isolation launch argv
- 고정 4 MiB output cap, snapshot entry/path/file/total cap
- 모든 validation의 단일 canonical run ID와 정확한 `<run>/receipt.json`

알 수 없는 필드, schema 1/2, 추가 bind, 뒤늦게 추가된 `/workspace`, 스냅샷에 고정되지 않은 코드 경로는 fail-closed 처리한다.

## 의도적인 NO_GO

- Windows/macOS: 동등한 AppContainer/restricted-token backend가 아직 없다.
- GPU 작업: 현재 backend는 NVIDIA device/driver allowlist를 증명하지 못하므로 GPU 0~5 요청도 실행 전 거부한다. GPU 6·7은 어떤 경우에도 노출하지 않는다.
- Bubblewrap 미설치, user namespace 비활성화, 관리자 경로 변조 가능 상태.
- 현재 호스트에 배포·독립 검증된 root-owned immutable snapshot broker 부재.
- 실제 root Linux에서 runtime·bwrap·snapshot·cleanup attestation을 end-to-end
  재검증한 integration evidence 부재.

## Linux root-broker CI 경계

`linux-root-broker` CI는 root broker의 커밋 snapshot transport만 독립된
플랫폼 인벤토리로 실행합니다. 고정 test ID와 inventory hash는
`scripts/validate_snapshot_broker_integration_inventory.py`가 관리하고,
일반 Python 인벤토리는 해당 파일을 정확히 하나만 명시적으로 위임한 뒤
나머지 모든 테스트를 0 skip으로 실행합니다.

broker-only CI는 `bwrap`를 사용하지 않으므로 해당 바이너리의 존재나 격리를
증명하지 않습니다. `bwrap`는 향후 dedicated verifier/root-runner Linux
E2E에서 필수 전제조건으로 별도 검증하며, 없으면 skip하지 않고 실패해야
합니다. 두 인벤토리의 증명 범위를 합쳐 표시해서는 안 됩니다.

이 CI가 통과해도 Trusted Runner 전체 영수증이나 task trust projection의
신뢰성을 뜻하지 않습니다. broker signing-oracle P0의 코드 수정 여부와
무관하게 별도 runner-to-projection Linux 인벤토리가 통과하기 전까지
`BROKER_PROOF_SCOPE=broker-snapshot-only`와
`PHASE1_RELEASE_ELIGIBLE=false`를 유지합니다. broker-only 증거를 Phase 1
검증 완료로 사용하는 것은 fail-closed 위반입니다.

CPU·메모리·scratch quota는 별도 cgroup 단계가 필요하다. 이 문서는 현재 증명 가능한 범위와 아직 증명하지 못한 범위를 분리하며, 후자를 성공으로 표시하지 않는다.
