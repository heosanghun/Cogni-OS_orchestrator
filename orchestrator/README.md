# Codex–Antigravity pair workbench

이 디렉터리의 현재 실행 경로는 다음 세 파일입니다.

- `pair.ps1`: init, probe, new-task, status, list, stop 제어
- `pair-sidecar.ps1`: pin 검증, 격리, R1/R2, 후보 생성
- `pair-process-runner.ps1`: 제한 시간과 중단 요청을 적용한 로컬 자손 실행

## 빠른 확인

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\orchestrator\pair.ps1 probe `
  -WorkspaceRoot $PWD
```

## 새 pair task

```powershell
$PairId = (
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\orchestrator\pair.ps1 new-task `
    -WorkspaceRoot $PWD `
    -Title "읽기 전용 검증 목표" `
    -Goal "완료 조건, 중단 조건, 재현 명령" `
    -TargetWorkspace "C:\Project\Target"
  | Select-Object -Last 1
).Trim()

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\orchestrator\pair.ps1 status `
  -WorkspaceRoot $PWD `
  -TaskId $PairId
```

실제 Sidecar 인자는 환경별로 pin한 Antigravity language server,
Codex executable, Git 및 runner의 절대 경로와 SHA-256을 요구합니다.
자동으로 발견한 새 binary를 신뢰하지 않습니다.

## 신뢰 경계

- 두 모델 모두 대상 Git workspace를 읽기 전용으로 분석합니다.
- Antigravity outbox 결과는 broker-only import 경로로 이동하고 hash,
  DONE, front matter와 quiescence를 다시 검증합니다.
- Codex 결과도 별도 invocation evidence와 seal로 검증합니다.
- 중단은 서버측 생성을 취소한다고 주장하지 않고 결과 수락 권한을
  철회합니다.
- `PAIR_CANDIDATE`는 task plane의 `verified` 또는
  `EXECUTION_AUTHORIZED`와 동의어가 아닙니다.
- Antigravity의 추가 역할 라벨은 같은 모델 계열이므로 독립 검증자가
  아닙니다. 최종 판정은 Python task plane에서 Codex가 별도 증거로
  수행합니다.

전체 설명은 `..\PAIR_FAST_START_KO.md`, 거버넌스는
`..\AGENTS.md`를 참고합니다.
