# Privileged Snapshot Broker 배포 게이트

이 구성요소는 Linux 전용입니다. Windows에서는 설계상 `NO_GO`이며 경로 기반
스냅샷이나 동일 사용자 `chmod`로 자동 강등하지 않습니다.

## 신뢰 경계

- daemon은 root로 실행되고 고정 소켓
  `/run/cogni-os/trusted-snapshot-broker.sock`만 사용합니다. 소켓은
  `root:cogni-broker`, mode `0660`이며 명시적으로 그룹에 등록된 비-root
  UID/GID만 `SO_PEERCRED` 검사 후 허용합니다.
- 요청은 5초 connection timeout, 8 worker/16 in-flight 상한, exact schema,
  TTL, 영속 nonce
  `O_EXCL` 소비를 모두 통과해야 합니다.
- 비특권 runner가 고정 Git 정책으로 커밋을 먼저 검사·materialize한 뒤 전체
  트리를 caller 소유 `0555` 디렉터리와 `0444/0555` 파일로 봉인합니다.
- client는 봉인한 source directory FD 하나를 `SCM_RIGHTS`로 전달합니다.
  root daemon은 경로·Git·actor 저장소 metadata를 사용하지 않고 descriptor-relative
  `openat/O_NOFOLLOW/O_EXCL` 복사만 수행합니다.
- client는 응답으로 정확히 하나의 `O_PATH` 디렉터리 FD를 `SCM_RIGHTS`로 받아
  device/inode/uid/mode를 서명된 acquire 문서와 비교합니다.
- broker 서명은 복사된 snapshot byte provenance와 cleanup만 증명합니다. 커밋과
  tree의 진위는 비특권 runner가 별도의 source 검증으로 입증해야 하며 broker
  서명만으로 source authenticity를 주장할 수 없습니다.
- snapshot 삭제는 daemon만 수행합니다. 서명된 cleanup ack가 없으면 해당
  실행은 신뢰 증거가 아닙니다.
- acquire와 cleanup은 task/attempt/actor/run/validation-contract에 결합되고,
  cleanup은 최종 receipt에서 cleanup 서명만 제외한 비순환 preimage SHA-256에
  결합됩니다. 다른 실행의 과거 proof 재사용은 거부합니다.
- lease record는 root 전용 `0600` canonical JSON으로 bounded 저장됩니다.
  만료 lease와 daemon 재시작 시 orphan/부분 snapshot은 identity 확인 후 broker가
  정리합니다.

## 비대칭 키와 OpenSSL provisioning

`scripts/install_snapshot_broker.sh`는 다음 고정 파일을 생성합니다.

- 먼저 `/var/lib/cogni-os/snapshot-broker/cogni_os.whl`에 root 소유,
  group/world 비쓰기 wheel을 별도로 staging해야 합니다. 현재 작업 디렉터리나
  actor 상대 경로에서는 root 설치하지 않습니다.
- immutable runtime: `/usr/local/lib/cogni-os/snapshot-broker-v1`; `--copies` venv의
  interpreter hash, package tree hash, wheel hash를 root-owned
  `/etc/cogni-os/snapshot-broker/runtime.json`에 canonical JSON으로 고정합니다.
- systemd ExecStart는
  `/usr/local/lib/cogni-os/snapshot-broker-v1/venv/bin/python -I -m cogni_os.snapshot_broker serve`
  로 고정됩니다.

- private key: `/etc/cogni-os/snapshot-broker/ed25519-private.pem`,
  `root:root`, mode `0600`; daemon 외 읽기 금지
- public key: `/etc/cogni-os/snapshot-broker/ed25519-public.pem`,
  `root:root`, mode `0644`; runner/projection 검증 전용
- OpenSSL digest: `/etc/cogni-os/snapshot-broker/openssl.sha256`,
  `root:root`, mode `0644`

신뢰 디렉터리는 `root:root 0755`로 고정해 비특권 client가 public key,
OpenSSL digest와 runtime manifest를 읽어 독립 검증할 수 있게 합니다. private
key만 `root:root 0600`이고, 나머지 세 공개 자료는 `root:root 0644`입니다.
runtime manifest는 고정 공개 필드만 허용하며 private key, secret, token 또는
credential을 포함하면 CI가 실패합니다. 어느 경로도 group/world writable이면
설치와 client preflight가 실패합니다.

서명은 HMAC/shared secret가 아닌 Ed25519 detached signature입니다. 구현은
고정 `/usr/bin/openssl`만 실행하며 매 서명·검증 전에 위 관리자 SHA-256과
실제 바이너리를 비교합니다. 키 또는 SHA 파일의 경로 체인에 symlink,
비-root 소유권, group/world write가 있으면 즉시 실패합니다.

설치 후 실제 runner 계정을 `cogni-broker` 그룹에 명시적으로 등록해야 합니다.
자동으로 임의 사용자를 등록하지 않습니다.

## 완료 판정

서비스 설치만으로 완료가 아닙니다. root Linux에서 실제 daemon/client
integration test, FD 전달, acquire 서명, verifier 실행, cleanup 서명과
read-side 재검증을 모두 통과하기 전에는 Phase 1 상태를 `NO_GO`로 유지합니다.

### 필수 CI 인벤토리와 증명의 한계

`.github/workflows/monitoring-ci.yml`의 `linux-root-broker` 작업은
`ubuntu-24.04`에서 로컬 wheel을 네트워크 없이 빌드한 뒤 root 소유 staging,
immutable runtime, 전용 `cogni-broker` 그룹과 systemd 서비스를 실제로
설치합니다. 테스트는 등록된 비-root 계정으로만 실행하며 transient unit에서
`AF_UNIX` 외 주소군과 IP egress를 차단합니다. GPU device node가 하나라도
있거나 Git, OpenSSL, `/usr/bin/python3.12`, systemd 등 실제 사용되는 고정
전제조건이 없으면 skip하거나 네트워크 설치로 보완하지 않고 실패합니다.
이 snapshot transport 인벤토리는 `bwrap`를 실행하거나 검증하지 않습니다.
`bwrap`는 향후 별도 verifier/root-runner Linux E2E의 필수 무-skip
전제조건이며, 이 broker-only 결과로 대체할 수 없습니다.
GitHub checkout은 다른 UID가 소유하므로 `--no-local --no-checkout`으로
비특권 workspace에 복제한 뒤 정확한 `GITHUB_SHA`를 detached checkout하고
clean 상태를 확인합니다. `--no-hardlinks`만으로 소유권 검사를 우회하지 않습니다.

CI의 `cogni-ci` 계정은 `/bin/bash`를 가진 의도적인 adversarial transport
client입니다. 향후 no-login `cogni-verifier` 운영 주체나 독립 검증자로
간주하지 않으며 workflow의 `BROKER_CLIENT_ROLE`도 이를 고정합니다.

통합 테스트 파일은 일반 Python discovery에서 정확히 한 파일만 분리됩니다.
`scripts/validate_snapshot_broker_integration_inventory.py`가 파일 존재,
정확한 test ID·개수·인벤토리 SHA-256, workflow 위임과 action SHA pin을
검증합니다. 따라서 Windows/일반 Python 인벤토리는 0 skip이어야 하며,
Linux 통합은 무음 누락되지 않습니다.

이 작업의 증명 범위는 `broker-snapshot-only`입니다. 즉 root daemon provenance,
Ed25519 envelope 검증, 양방향 `SCM_RIGHTS` FD 전달, caller가 선언한 snapshot
manifest와 복사 byte의 동일성, 서명된 cleanup과 빈 snapshot/lease store만
증명합니다. source commit/tree authenticity는 이 broker 증명의 범위 밖입니다. signing-oracle P0
수정이 코드에 반영되더라도 별도 runner-to-projection Linux 증거가 통과하기
전에는 이 성공을 validator execution trust, 독립 검증 또는 Phase 1 GO로
승격하지 않습니다. workflow와 validator는
`phase1_release_eligible=false`, `validator_execution_trusted=false`를 고정합니다.
