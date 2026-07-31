# Cogni-OS Orchestrator

Cogni-OS Orchestrator는 **Codex 지휘자 + Antigravity 수행자**를 위한
evidence-first 작업 제어면입니다. 핵심 산출물은 에이전트의 설명이 아니라
재현 가능한 명령, 테스트 결과, SHA-256 증거 묶음과 HMAC 서명
append-only 원장입니다.

## 현재 운영 구조

```text
Codex conductor
  ├─ 목표 분해·task 생성·권한 경계
  ├─ Antigravity 구현 결과 수신
  ├─ 별도 재현 증거 생성
  └─ 책임 accept/reject 및 release gate

Antigravity worker/advisor
  ├─ 허용된 범위의 구현·테스트
  ├─ 보고서 + evidence manifest 제출
  └─ pair workbench 읽기 전용 자문

Evidence plane
  ├─ ledger/events.jsonl
  ├─ tasks/
  ├─ submissions/
  ├─ reports/
  └─ 검증된 monitoring snapshot
```

`antigravity-verifier`는 별도 이름을 사용하더라도 수행자와 같은
`google-antigravity` 모델 계열입니다. 따라서 Antigravity가 만든 결과에
대한 독립 검증자가 아니며, Python 신뢰 게이트도 이를 같은 모델 계열로
판정해 거절합니다. 최종 검증 책임자는 별도 증거를 재생성한 Codex입니다.

## 신뢰 상태 기계

```text
pending → claimed → running → submitted → verified → archived
                                   └────→ rejected
```

- task lease와 허용 write root로 수행 범위를 고정합니다.
- 제출 증거와 검증 증거는 서로 다른 manifest여야 합니다.
- known-answer 명령은 신뢰 runner가 다시 실행합니다.
- actor 라벨이 아니라 control principal, canonical model family,
  alias lineage로 독립성을 판정합니다.
- 원장·projection 불일치 또는 증거 누락은 fail-closed입니다.

## 설치

Python 3.10 이상에서:

```powershell
python -m pip install -e .
```

## 워크스페이스 초기화

```powershell
cogni init .\cogni-workspace `
  --name "Cogni-OS Production Workspace" `
  --orchestrator codex `
  --control-principal codex-conductor `
  --model-family openai-codex `
  --preset cogni-codex-antigravity

cogni doctor .\cogni-workspace
```

## task 실행

Codex가 task를 생성합니다.

```powershell
cogni task add .\cogni-workspace `
  --actor codex `
  --id T-101 `
  --owner antigravity `
  --title "Core validation 구현" `
  --description "완료 조건과 재현 명령을 포함한 단일 목표" `
  --allow-write src `
  --allow-write tests
```

Antigravity가 lease를 받아 실행하고 서로 다른 보고서·manifest를
제출합니다.

```powershell
cogni task claim .\cogni-workspace --actor antigravity --id T-101
cogni task start .\cogni-workspace `
  --actor antigravity --id T-101 --lease-token "<CLAIM_TOKEN>"
cogni task submit .\cogni-workspace `
  --actor antigravity --id T-101 --lease-token "<CLAIM_TOKEN>" `
  --report .\cogni-workspace\reports\antigravity\T-101.md `
  --evidence .\cogni-workspace\reports\antigravity\T-101.evidence.json
```

Codex는 별도 환경에서 재현한 검증 manifest로 최종 판정합니다.

```powershell
cogni task verify .\cogni-workspace `
  --actor codex `
  --id T-101 `
  --decision accept `
  --note "Known-answer와 회귀 검사를 별도 재현함" `
  --evidence .\cogni-workspace\reports\codex\T-101.verifier.evidence.json
```

## 읽기 전용 pair workbench

`orchestrator/pair*.ps1`은 Codex와 Antigravity가 같은 Git snapshot을
읽고 계획을 교차 검토하는 보조 경로입니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\orchestrator\pair.ps1 probe `
  -WorkspaceRoot $PWD

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\orchestrator\pair.ps1 new-task `
  -WorkspaceRoot $PWD `
  -Title "검증 가능한 단일 목표" `
  -Goal "완료 조건·중단 조건·재현 명령" `
  -TargetWorkspace "C:\Project\Target"
```

`PAIR_CANDIDATE`는 읽기 전용 계획 후보입니다. 제품 변경이나
릴리스 승인을 의미하지 않습니다. 자세한 절차는
`PAIR_FAST_START_KO.md`를 참고합니다.

## 검증

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s src\cogni_os\tests -v

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\pair_workbench_test.ps1

npm run check
npm test
```

## 관제

로컬:

```powershell
cogni dashboard .\cogni-workspace --port 8484
```

Cloudflare 실시간 관제의 D1, HMAC V2 keyring, 키 회전 및 fail-closed
배포 절차는 `docs/LIVE_MONITORING_DEPLOYMENT_KO.md`에 있습니다.

## Phase 1~11 실행 로드맵

계획을 문서에만 두지 않고 검증 가능한 task graph로 등록합니다.

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m cogni_os.cli roadmap bootstrap C:\comunity `
  --actor codex `
  --owner antigravity

python -m cogni_os.cli roadmap status C:\comunity
```

진행률은 Phase task 중 `verified` 또는 `archived` 상태만 계산합니다.
상세 계약은 `docs/PHASE_1_11_EXECUTION_PLAN_KO.md`에 있습니다.
