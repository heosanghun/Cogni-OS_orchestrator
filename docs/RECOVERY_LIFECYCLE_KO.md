# 검증·임대 복구 경계

이 문서는 프로세스 종료나 호스트 재시작 뒤에도 원장을 기준으로 안전하게
복구하기 위한 규칙을 정의합니다. 복구는 검증을 성공으로 간주하는 기능이
아니며, 불완전한 실행은 실패로 닫고 이미 서명된 결과만 투영합니다.

## 검증 실행

- `verification.started`는 32자리 `run_id`와 작업 `attempt`를 고정합니다.
- 시작 이벤트는 `task.verify` 영수증과 actor, verifier identity, verifier/worker
  manifest, validation-contract 입력 hash를 함께 고정합니다. terminal 이벤트는 이
  값들을 그대로 반복해야 하며 하나라도 다르면 수명주기 감사에서 거부됩니다.
- 같은 `run_id`에는 `verification.failed`, `task.verified`, `task.rejected` 중
  정확히 하나만 터미널 이벤트로 존재할 수 있습니다.
- `started`만 남은 실행은 `doctor`에서 `verification_lifecycle` 오류로
  보고되어 워크스페이스를 비정상 상태로 만듭니다.
- `task reconcile-verification`은 검증 명령을 다시 실행하지 않습니다.
  터미널이 없으면 `recovery/interrupted_error`로 한 번만 닫고, 터미널이
  있으면 최신 서명 작업 스냅샷으로 JSON 투영만 복원합니다.
- 같은 `run_id`를 다시 복구해도 터미널 이벤트를 추가하지 않습니다.
- reconciliation 영수증은 원래 task/run/attempt에 별도로 결합됩니다. 외부 broker로
  actor OS 격리가 입증되지 않은 동일 사용자 로컬 키 환경에서는 명령이
  `CAPABILITY_UNATTESTED`로 실패하며 성공으로 복구하지 않습니다.

```powershell
$env:COGNI_ACTOR_CAPABILITY_SECRET = '<OS 비밀 채널에서 받은 값>'
cogni task reconcile-verification C:\workspace `
  --actor codex --id P01 --run-id <32자리-run-id>
```

## 작업 임대

- 새 임대는 bearer token과 별도로 `session_id`, `issued_at`, `expires_at`을
  서명된 작업 스냅샷에 기록합니다.
- 정상 복구는 최신 서명 이벤트가 `task.claimed`, `task.started`,
  `task.heartbeat` 중 하나이고 해당 세션의 임대가 실제 만료된 경우에만
  허용됩니다. 건강한 임대는 선점할 수 없습니다.
- 레거시 임대처럼 서명된 세션 식별자가 없으면 정상 복구는 실패로 닫힙니다.
- 예외 강제 복구는 별도 actor capability가 필요하고
  `task.lease_force_recovered`로 일반 복구와 구분해 서명됩니다.
- 두 복구 모두 기존 `attempt`를 유지하고 token 또는 token hash를 이벤트에
  기록하지 않습니다.

```powershell
# 만료된 서명 세션의 정상 복구
cogni task recover-lease C:\workspace `
  --actor codex --id P01 --reason '서명 세션 만료 확인'

# 예외 강제 복구: 환경 비밀이 없거나 틀리면 원장 기록 전에 실패
$env:COGNI_ACTOR_CAPABILITY_SECRET = '<OS 비밀 채널에서 받은 값>'
cogni task recover-lease C:\workspace `
  --actor codex --id P01 --reason '사고 대응 승인' --force
```

운영 워크스페이스 `C:\comunity`는 테스트에서 사용하지 않습니다. 회귀
테스트는 임시 워크스페이스와 임시 외부 capability 저장소만 사용합니다.
