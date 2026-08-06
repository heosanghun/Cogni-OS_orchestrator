# Actor Capability 보안 경계

## 왜 필요한가

기존 워크스페이스 HMAC 키는 append-only 원장의 무결성은 보장하지만, 호출
프로세스의 신원은 보장하지 않는다. 워크스페이스를 읽고 실행할 수 있는
프로세스가 `--actor codex`를 입력하면 같은 HMAC 키로 Codex 명의 이벤트를
만들 수 있었다. 따라서 actor 문자열과 에이전트 역할 레코드는 **인증 수단이
아니다**.

`cogni_os.actor_capability`는 워크스페이스 신뢰 루트와 분리된 다음 경계를
추가한다.

- 키 레코드와 replay nonce는 워크스페이스·저장소 밖에 둔다.
- proof와 영수증은 `workspace_id + actor + operation + task_id + run_id +
  task_attempt + nonce + key_version + issued_at + expiry`에 결합한다. 작업·실행·
  시도가 없는 연산도 필드를 생략하지 않고 명시적 `null`로 서명한다.
- 서명 비교는 `hmac.compare_digest`를 사용하고 nonce는 `O_EXCL` 파일로 한
  번만 소비한다.
- secret은 argv, 원장, 보고서, 저장소에 기록하지 않는다. CLI는 환경에서
  secret을 읽은 즉시 `pop`하여 자식 프로세스가 상속하지 못하게 한다.
- guard/key/proof 중 하나라도 없거나 틀리면 워크스페이스 lock·원장 append
  이전에 fail-closed 한다.

## 과장하지 않는 위협 모델

Windows DPAPI는 현재 Windows 사용자의 at-rest 키를 보호한다. 그러나 Codex와
Antigravity가 **같은 Windows 사용자**로 실행되면 DPAPI만으로 둘을 분리했다고
입증할 수 없다. 이 구현이 입증하는 것은 다음 범위뿐이다.

1. 워크스페이스 파일과 공유 ledger key만 가진 프로세스는 conductor secret
   없이 privileged mutation을 실행할 수 없다.
2. bwrap/컨테이너/별도 OS 계정 정책으로 capability home 접근이 차단된
   executant는 conductor를 사칭할 수 없다.

같은 사용자로 실행되는 임의 프로세스 전체에 대한 강한 격리는 주장하지
않는다. 강한 격리는 별도 OS principal 또는 외부 secret broker와, capability
home ACL 접근 불가를 재현한 attestation이 필요하다. 이 attestation이 없는
현재 posture에서 `production release evidence collect`와 `release gate issue`는
모두 `CAPABILITY_UNATTESTED`로 **NO_GO**다. API가 반환하는
`workspace_process_impersonation_blocked_without_credential`도 같은 사용자
격리가 입증되기 전에는 `false`이며, 외부 키 저장소가 있다는 사실만으로 이를
`true`로 올리지 않는다.

소비 영수증 v2는 원장에 저장된 뒤에도 활성 키 또는 보존된 과거 receipt key로
서명을 다시 검증하고, 별도 consumption marker의 content hash와 대조한다. 따라서
평문 영수증, 필드 변조, 다른 task/run/attempt로의 재사용, marker 삭제·변조는
거부된다. 다만 이 read-side 검증도 동일 사용자 로컬 HMAC에 불과하므로 독립된
권한 증명은 아니다. `require_independent_trust_root=true`인 신뢰 핵심 경로는 외부
broker 또는 공개 검증 가능한 trust root가 공급되기 전까지 항상 NO_GO다.

## Bootstrap과 회전

기존 워크스페이스는 자동 마이그레이션하지 않는다. 정상 CLI는 bootstrap
guard를 만들 수 없다. 설치 관리자 또는 OS 관리자가 ACL로 격리된 setup
context에서 `ActorCapabilityAuthority.provision_guard()`를 한 번 실행하고,
동일한 32-byte 이상 난수 secret을 conductor secret 채널로 전달해야 한다.

그 후 conductor는 secret을 argv가 아닌 환경으로 주입한다.

```powershell
$env:COGNI_ACTOR_CAPABILITY_BOOTSTRAP_SECRET = '<secret-manager injection>'
cogni capability bootstrap C:\comunity --actor codex
```

guard가 없으면 위 명령은 아무 키도 만들지 않고
`CAPABILITY_UNPROVISIONED` 상태를 유지한다. 상태 확인에는 secret이 필요 없다.

```powershell
cogni capability status C:\comunity --actor codex
```

회전은 기존 key의 `capability.rotate` one-time proof와 새 secret을 모두 요구한다.

```powershell
$env:COGNI_ACTOR_CAPABILITY_SECRET = '<current secret-manager injection>'
$env:COGNI_ACTOR_CAPABILITY_NEW_SECRET = '<new secret-manager injection>'
cogni capability rotate C:\comunity --actor codex
```

old proof replay, old secret, 다른 workspace/actor/operation proof는 모두 거부된다.
회전은 actor별 외부 lock 안에서 key version compare-and-swap으로 수행되어 동시
회전 두 건 중 하나만 성공한다. 과거 감사 영수증 검증용 key는 버전별로 보호 저장
하지만 새 proof 발행에는 절대 사용하지 않는다.
환경 변수는 명령 진입 즉시 제거되며 명령 출력에는 secret/proof가 포함되지
않는다.

## 보호되는 변경 경로

- agent 등록
- task 생성
- 독립 verification 및 verification restatement/reconciliation
- Phase 1~11 roadmap bootstrap
- 강제 lease recovery (정상 만료 recovery는 별도 signed-expiry 정책)
- production release evidence 수집
- release gate 발행

release evidence 수집이 성공한 미래의 attested 환경에서는 소비된 capability의
범위 영수증이 content-addressed bundle과 signed ledger event 양쪽에 결합된다.
release gate 검증은 두 영수증이 동일하고
`workspace + codex + release.evidence.collect` 범위인지 확인한다. 이 영수증은
감사 결합 정보일 뿐, 재사용 가능한 bearer token으로 승인하지 않는다.

`verify`, `reconcile-verification`, verification restatement, 강제 lease recovery는
모두 작업·run·attempt에 결합된 영수증을 요구한다. `verification.started`와 terminal
event는 actor, verifier identity, verifier/worker manifest, validation contract 입력,
동일 영수증을 함께 고정한다. 투영기와 release gate는 원장 문자열을 신뢰하지 않고
영수증과 consumption marker를 다시 검증한다.

읽기 전용 status와 release gate 검증은 capability가 없어도 실행할 수 있다.
