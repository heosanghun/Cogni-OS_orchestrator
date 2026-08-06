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
경로로 승인합니다. P01에서는 `doctor.healthy=true`와 동시에 과거 T-001과
후속 Phase 때문에 전체 `doctor.release_ready=false`임을 정직하게
확인합니다. 정확한 source commit, BUILD_BOUND 배포 commit, production
health/snapshot, replay·rollback dry-run 검증 중 하나라도 hashed evidence bundle로
확인되지 않으면 P01은 NO_GO로 유지합니다.

production 증거 수집은 Cloudflare API와 고정 production endpoint에 대한
읽기만 수행합니다. rollback은 과거의 서로 다른 production deployment가
실제로 존재하고 되돌릴 수 있는 대상인지 검증하는 dry-run receipt이며,
배포 변경·트래픽 전환·rollback mutation을 실행하지 않습니다.
선택한 deployment API 응답뿐 아니라 project API의 `canonical_deployment`를
같이 보존합니다. 현재 canonical URL이 실제로 제공하는 deployment ID와
고유 direct URL이 health/snapshot의 서버 소유 build attribution에 정확히
결합되어야 하며, commit만 같고 deployment가 다르면 검증은 실패합니다.

`/api/health`의 준비 상태는 두 층으로 분리합니다. D1 schema 1.2,
keyring, 불변 빌드 commit이 결합되어 `operational_ingest_ready=true`인 것은
publisher가 증거 수집을 시작할 수 있다는 의미입니다. 이것만으로 릴리스
귀속을 자체 승인하지 않습니다. 서버 health는
`release_attribution_ready=false`와
`release_evidence_state=API_EVIDENCE_REQUIRED`를 유지하며, 위 Cloudflare
project API 원문·deployment ID·direct URL을 별도 archive에 보존하고 signed
ledger와 known-answer validator가 대조한 이후에만 P01 릴리스 게이트가
승격될 수 있습니다.

운영 collector도 bootstrap trust와 application evidence를 분리합니다.
사용자 쓰기 가능한 checkout, reparse 경로, PATH/환경 변수로 선택된 실행
파일, 실행 중 SHA가 바뀐 파일은 secret을 읽기 전에 `NO_GO`입니다. 관리자
소유 불변 소스 루트와 고정된 Windows PowerShell/Git/Program Files Python을
배치한 뒤에만 DPAPI secret을 복호화하고 signed snapshot을 전송합니다.

GPU 릴리스 증거는 telemetry, compute process, Docker DeviceRequests,
Slurm/예약 상태를 모두 측정한 경우에만 `MEASURED`입니다. 수집 비활성화,
도구 부재, 권한 오류, 생략은 성공이 아니라 `UNMEASURED · NO_GO`입니다.
특히 금지 GPU 6·7은 낮은 사용률과 무관하게 process/container/reservation
증거가 하나라도 발견되면 정책 위반으로 처리합니다.

## 5. production 증거부터 immutable gate까지의 실행 순서

`reports/`와 `runs/`는 staging입니다. 아래 `release evidence collect`가
`scripts/validate_p01_python.py`의 `ARTIFACT_FILES`에 선언된 정확한 산출물
집합(현재 15개)과 `bundle.json`을 content-addressed archive로 복사하고
서명 원장에 결합한 뒤에만 production 증거가 됩니다. API token은 CLI
인자가 아니라 현재 프로세스 환경에서만 읽습니다.

15개 계약은 production health/snapshot의 body와 capture 4개, 현재
Cloudflare deployment/project의 raw body와 capture 4개, rollback
deployment/project의 raw body와 capture 4개, 파생된 현재 deployment 증거,
rollback target 증거, rollback dry-run receipt 3개입니다. 문서의 숫자나
파일명보다 validator의 exact key set과 hash/size 검증이 최종 기준입니다.

증거 수집 전 protected production 단계에서 migration과 배포 귀속을 먼저
검증합니다. 아래 단계가 하나라도 실패하면 publisher를 재시작하거나 P01을
승인하지 않습니다.

```powershell
npx wrangler d1 migrations list cogni-os-monitoring --remote
npx wrangler d1 migrations apply cogni-os-monitoring --remote
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA table_info(monitor_schema_floors);"
# 그 다음 main Pages 배포 후 /api/health의 BUILD_BOUND, source commit,
# minimum_release_snapshot_schema=1.2를 확인합니다.
```

```powershell
$env:CLOUDFLARE_API_TOKEN = "<read-only deployment token>"
cogni release evidence collect C:\comunity `
  --actor codex `
  --cloudflare-account-id <ACCOUNT_ID> `
  --deployment-id <CURRENT_PRODUCTION_DEPLOYMENT_ID> `
  --deployment-source-commit <CURRENT_40_HEX_COMMIT> `
  --rollback-deployment-id <PRIOR_PRODUCTION_DEPLOYMENT_ID> `
  --rollback-source-commit <PRIOR_40_HEX_COMMIT>
Remove-Item Env:CLOUDFLARE_API_TOKEN
```

그 다음 trusted validator 출력과 독립 검증을 거쳐 P01을 승인합니다.
P01의 `task.verified` 사건은 위 `release.evidence_collected` 사건보다 뒤에
있어야 합니다. 모든 current-release task가 같은 HEAD에서 검증되고,
file-backed runtime attestation이 신선한 상태에서 immutable gate를
발행하고 즉시 재검증합니다.

```powershell
cogni release gate issue C:\comunity `
  --actor codex `
  --attesting-agent <ATTESTED_AGENT_ID>
cogni release gate status C:\comunity `
  --expected-source-commit <CURRENT_40_HEX_COMMIT>
```

gate는 tracked `release/RELEASE_GATE.json`을 읽지 않습니다. 유일한 PASS
근거는 `archive/release-gates/<commit>/<sha256>/release-gate.json`과 정확히
결합된 `release.gate_issued` signed ledger event입니다.

## 6. 소스 변경과 운영 증거 변경의 분리

`ledger/events.jsonl`, `tasks/*.json`, `reports/`, `runs/`, `submissions/`는
실행 중 계속 추가되는 운영 증거입니다. 검증된 운영 변경은
`source.operational_state`의 개수와 SHA-256 지문으로 공개하되 소스 코드
오염으로 계산하지 않습니다. 운영 경로 안의 미분류 파일, 유효하지 않은
원장, projection 불일치는 `UNVERIFIED_OPERATIONAL_STATE`와 `NO_GO`를
발생시킵니다.

운영 파일은 경로만으로 검증되지 않습니다. `task.submitted`,
`task.verified`, `task.rejected` signed ledger 사건에 파일 경로와 SHA-256이
같이 기록되어야 하며 현재 내용의 hash와 일치해야 합니다. 실행 가능한
확장자는 evidence 디렉터리 안에 있어도 미분류 소스로 취급합니다.

수집기는 자기 엔트리포인트의 SHA-256, 제어면 커밋 및 제어면 소스 상태를
`collector.attribution`에 넣습니다. 이 커밋과 운영 워크스페이스의
`source.git_commit`이 다르면 수집 API가 스냅샷을 거부합니다.
