# 네 개 AI 화면을 로컬 council에 연결하기

이 문서는 Antigravity, Cursor, Codex App, Claude를 `C:\comunity`의
로컬 메시지 버스에 연결하는 실제 시작점이다.

## 현재 상태

- 네 앱 화면이 열려 있는 것은 확인됐지만 `C:\comunity`에 연결됐다는
  뜻은 아니다.
- 현재 활성 task와 pending message는 없다. 지금 방 프롬프트를 실행하면
  `QUEUE_EMPTY` 또는 `WAITING_FOR_ADVISORS`가 정상이다.
- Markdown 파일은 GUI 채팅을 스스로 깨우지 않는다.
- `orchestrator\watch.ps1`은 상태와 timeout만 처리하며 모델을 호출하지
  않는다.
- 따라서 현재 모드는 `PREPARED_MANUAL`이다. 네 앱이 열린 한 turn 안에서
  `room.ps1 wait`를 계속 실행하면 live smoke loop는 가능하지만, 장기
  무인 운용에는 제품별 CLI/API/Sidecar/Scheduled adapter가 필요하다.

## 권장 연결

| 화면 | 연결 방식 | 역할 |
|---|---|---|
| Antigravity | `C:\comunity`를 Project에 추가하고 Local Mode | architecture advisor |
| Cursor | `C:\comunity`를 로컬 workspace로 열기 | code-structure advisor |
| Codex App | `C:\comunity`를 local project로 열기 | sole executor |
| Claude | 일반 웹 chat 대신 Claude Code Remote Control/Cowork local folder | evidence advisor |

일반 `claude.ai/chat`은 로컬 폴더를 실시간으로 읽지 못한다. 업로드한
파일은 snapshot일 뿐 local bus가 아니다. Claude 방은 먼저
`C:\comunity\CLAUDE.md`를 직접 읽을 수 있는지 시험해야 한다.

## 최초 한 번

```powershell
Set-Location C:\comunity

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\ensemble.ps1 init `
  -WorkspaceRoot C:\comunity

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\ensemble.ps1 probe `
  -WorkspaceRoot C:\comunity
```

제품 코드 대상은 clean Git 작업트리를 사용한다. 예:

```powershell
$TaskId = (
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File C:\comunity\orchestrator\ensemble.ps1 new-task `
    -WorkspaceRoot C:\comunity `
    -Title "한 가지 검증 가능한 목표" `
    -Goal "완료 조건, 실행할 테스트, 중단 조건을 구체적으로 기록" `
    -TargetWorkspace "C:\Project\System1.5"
  | Select-Object -Last 1
).Trim()

$TaskId
```

그 다음 아래 네 파일의 전체 내용을 해당 화면에 한 번씩 붙여넣는다.

- `ensemble\manual-ui\prompts\ANTIGRAVITY_BOOTSTRAP_KO.md`
- `ensemble\manual-ui\prompts\CURSOR_BOOTSTRAP_KO.md`
- `ensemble\manual-ui\prompts\CODEX_APP_BOOTSTRAP_KO.md`
- `ensemble\manual-ui\prompts\CLAUDE_BOOTSTRAP_KO.md`

메모장으로 열거나, 아래처럼 한 방의 프롬프트를 클립보드에 복사할 수
있다. 파일명만 각 agent에 맞게 바꾼다.

```powershell
Get-Content -Raw -Encoding UTF8 `
  C:\comunity\ensemble\manual-ui\prompts\ANTIGRAVITY_BOOTSTRAP_KO.md |
  Set-Clipboard
```

## 방 도우미

각 에이전트는 자기 pending message만 확인한다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\room.ps1 next `
  -WorkspaceRoot C:\comunity `
  -Agent antigravity
```

새 메시지를 최대 10분 기다리려면:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\room.ps1 wait `
  -WorkspaceRoot C:\comunity `
  -Agent antigravity `
  -TimeoutSeconds 600
```

응답을 envelope의 `output_path`에 쓴 뒤, 출력된
`ROOM_MESSAGE_PATH`를 사용해 제출한다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\room.ps1 submit `
  -WorkspaceRoot C:\comunity `
  -Agent antigravity `
  -MessagePath "<ROOM_MESSAGE_PATH>"
```

`room.ps1`은 stale inbox를 제외하고 coordinator가 발행한 pending
message만 선택한다. 모델을 호출하거나 GUI를 깨우지는 않는다.

## 대화 순서

```text
Antigravity + Cursor + Claude: R1 blind advice
  -> 세 advisor: R2 cross-critique
  -> Codex App: executor plan
  -> 세 advisor: plan vote
  -> Codex App: authorized implementation + tests
  -> 세 advisor: post-review vote
  -> READY_TO_COMMIT
```

이 구조는 자유로운 난상토론보다 의도적으로 엄격하다. R1을 서로 보지
않고 작성해야 세 모델이 한 목소리로 수렴하는 집단사고를 줄일 수 있다.

## 승인창 원칙

프롬프트는 앱 자체의 보안창을 제거할 수 없다. 각 앱에서 허용하는 경우
프로젝트 범위를 `C:\comunity`와 명시된 target으로 좁히고, 읽기와
`powershell.exe ... room.ps1` 실행만 지속 허용한다. broad
`Unrestricted`, `yolo`, 전체 디스크 허용은 사용하지 않는다.

각 agent는 사용자에게 직접 승인 질문을 반복하지 않는다. hard stop은
자신의 산출물에 기록하고, coordinator만 `APPROVAL_PACKET.md` 하나를
만들어 같은 state/version에 대해 한 번만 요청한다.

## GitHub 경계

- 대화 메시지를 매번 GitHub에 push하지 않는다.
- advisor와 executor는 직접 push, deploy, merge하지 않는다.
- 검증된 `DECISION.md`, `MINORITY_REPORT.md`, evidence index와 candidate
  commit만 task branch checkpoint로 게시한다.
- `main` merge와 공개 발표는 별도 인간 경계다.

세부 설명은 `ensemble\manual-ui\README_KO.md`와
`ensemble\control\RUN_MODE.md`를 따른다.
