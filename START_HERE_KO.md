# Cogni-OS 시작하기

현재 공식 경로는 Python `cogni` task plane과 Codex–Antigravity
읽기 전용 pair workbench 두 가지입니다. 사용자가 에이전트 사이의
메시지를 복사해 전달하지 않습니다.

## 1. 사전 확인

```powershell
Set-Location C:\comunity

$env:PYTHONPATH = "$PWD\src"
python -m cogni_os.cli status .
python -m cogni_os.cli doctor .
```

설치된 console script를 사용하면 `python -m cogni_os.cli` 대신
`cogni`를 사용할 수 있습니다. 기존 workspace가 아니라 새 경로라면:

```powershell
cogni init .\workspace `
  --name "Cogni-OS Workspace" `
  --orchestrator codex `
  --control-principal codex-conductor `
  --model-family openai-codex `
  --preset cogni-codex-antigravity
```

## 2. 역할의 실제 의미

| 주체 | 운영 책임 | 독립 검증 여부 |
|---|---|---|
| Codex | 지휘, task 생성, 경계 설정, 별도 재현, 최종 판정 | 책임 검증자 |
| Antigravity | 구현·테스트·증거 제출 또는 읽기 전용 자문 | 자기 결과 검증 불가 |
| `antigravity-verifier` | 같은 계열의 추가 검토 라벨 | 독립 검증 아님 |

독립성은 이름으로 결정하지 않습니다. 같은 canonical model family,
같은 control principal 또는 공유 alias lineage는 신뢰 게이트에서
거절됩니다.

## 3. task plane

Codex가 한 번에 하나의 검증 가능한 목표를 등록합니다.

```powershell
cogni task add . `
  --actor codex `
  --id T-101 `
  --owner antigravity `
  --title "단일 구현 목표" `
  --description "완료 조건, 테스트, 중단 조건, 재현 명령" `
  --allow-write src `
  --allow-write tests
```

Antigravity가 claim 응답의 lease token을 사용해 실행·제출합니다.

```powershell
cogni task claim . --actor antigravity --id T-101
cogni task start . `
  --actor antigravity --id T-101 --lease-token "<CLAIM_TOKEN>"
cogni task submit . `
  --actor antigravity --id T-101 --lease-token "<CLAIM_TOKEN>" `
  --report .\reports\antigravity\T-101.md `
  --evidence .\reports\antigravity\T-101.evidence.json
```

Codex는 수행 manifest를 재사용하지 않고 별도 known-answer 실행으로
새 검증 manifest를 만든 뒤 판정합니다.

```powershell
cogni task verify . `
  --actor codex `
  --id T-101 `
  --decision accept `
  --note "별도 환경에서 재현 완료" `
  --evidence .\reports\codex\T-101.verifier.evidence.json
```

## 4. pair workbench

pair 경로는 두 주체가 동일한 Git snapshot을 읽고 R1/R2 검토와
계획 후보를 만드는 보조 평면입니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\pair.ps1 probe `
  -WorkspaceRoot C:\comunity

$PairId = (
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File C:\comunity\orchestrator\pair.ps1 new-task `
    -WorkspaceRoot C:\comunity `
    -Title "검증 가능한 계획 목표" `
    -Goal "완료 조건과 hard stop을 포함한 읽기 전용 분석" `
    -TargetWorkspace "C:\Project\Target"
  | Select-Object -Last 1
).Trim()

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\pair.ps1 status `
  -WorkspaceRoot C:\comunity `
  -TaskId $PairId
```

실제 adapter pin과 권한 경계가 준비된 호스트에서만
`pair-sidecar.ps1`을 구동합니다. binary SHA mismatch, write-boundary
위반, timeout 또는 변조는 `PAIR_SAFE_STOP`으로 끝납니다.
`PAIR_CANDIDATE`도 제품 수정·commit·push·배포 권한은 아닙니다.

상세 옵션과 증거 파일 구조는 `PAIR_FAST_START_KO.md`를 따릅니다.

## 5. 변경 후 필수 검증

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s src\cogni_os\tests -v

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\pair_workbench_test.ps1

npm run check
npm test
```

테스트를 실행하지 못했다면 완료로 표현하지 않고, 누락된 runtime과
재현 명령을 보고합니다.

## 6. 증거 보존

`ledger/`, `tasks/`, `submissions/`, `reports/`는 역사 증거입니다.
현재 문서나 코드와 맞지 않는 과거 기록이 있어도 삭제·수정하지 않고,
새 이벤트와 새 검증 결과로 교정합니다.
