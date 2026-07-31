# Phase 1 Release Truth 운영 절차

Phase 1의 목적은 과거 기록을 지우는 것이 아니라, 현재 신뢰 판정을
서명된 후속 사건으로 바로잡는 것입니다. `ledger/`, `tasks/`, `reports/`,
`submissions/`의 기존 파일은 삭제하거나 덮어쓰지 않습니다.

## 1. 정식 계약 등록

```powershell
cogni roadmap bootstrap C:\comunity --actor codex --owner antigravity
cogni roadmap status C:\comunity
```

등록은 멱등적입니다. 이미 존재하는 계약이 정식 계약과 다르면 자동으로
고치지 않고 실패하여 드리프트를 드러냅니다. `P01-TRUTH`는 선행 작업이
없고, 역사 증거 디렉터리를 쓰기 범위에 포함하지 않습니다.

## 2. 과거 검증의 append-only 정정

먼저 `doctor`에서 대상 검증의 ledger sequence와 독립성 실패 이유를
확인합니다.

```powershell
cogni doctor C:\comunity
```

같은 모델 계열의 수행자와 검증자가 만든 과거 `T-001` 승인은 다음과
같이 정정합니다. sequence를 지정하면 다른 검증 사건을 실수로 가리키는
것을 방지할 수 있습니다.

```powershell
cogni task restate-verification C:\comunity `
  --actor codex `
  --id T-001 `
  --status verification_disputed `
  --target-sequence <TASK_VERIFIED_SEQUENCE> `
  --reason "worker와 verifier가 같은 canonical model family이므로 독립 검증 요건을 충족하지 않음"
```

이 명령은 원래 `task.verified`의 sequence와 event hash에 결합된
`verification.restatement` 사건만 원장 끝에 추가합니다. 원래 task JSON,
검증 사건, 보고서와 증거 묶음은 변경하지 않습니다. 같은 상태와 이유로
재실행하면 새 사건을 중복 기록하지 않습니다. `verification_revoked`는
더 강한 최종 상태이며 이후 `verification_disputed`로 약화할 수 없습니다.

## 3. Doctor 판정 해석

- `healthy=true`: 원장·projection이 일치하고, 독립성 결함이 신뢰 가능한
  restatement로 빠짐없이 설명되었습니다.
- `release_ready=false`: 기록된 `verified` task 중 실제 신뢰 상태가
  disputed/revoked인 항목이 남아 있습니다.
- `unacknowledged_claims`: 신뢰 증거도 restatement도 없는 완료 주장입니다.
- `release_blockers`: 현재 릴리스에 포함할 수 없는 task입니다.

`healthy`는 감사 체계가 정직하다는 뜻이며 제품 완료를 의미하지 않습니다.

## 4. P01 검증 게이트

Antigravity는 `P01-TRUTH`의 변경과 worker evidence를 제출할 수 있지만,
같은 Antigravity 계열 검증자는 이를 독립 승인할 수 없습니다. Codex가
별도의 known-answer 명령을 trusted runner로 재실행하고, 다른 verifier
manifest와 원본 출력 hash를 만든 뒤에만 `cogni task verify --actor codex`
경로로 승인합니다. `doctor.release_ready`, 정확한 source commit, 배포
commit, replay·rollback 명령 중 하나라도 확인되지 않으면 P01은 NO_GO로
유지합니다.
