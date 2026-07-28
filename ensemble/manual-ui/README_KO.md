# 수동 UI 네 방 운용

네 개의 수동 채팅 화면은 파일이 생겼다는 이유만으로 서로를 호출하지
않는다. bootstrap 프롬프트는 역할과 처리 규칙을 초기화하지만 그 자체로
무인 daemon을 만들지 않는다.

## 방과 권한

| Agent ID | 소유 inbox/outbox | 제품 코드 |
|---|---|---|
| `antigravity` | 자기 방만 | 읽기 자문만 |
| `cursor` | 자기 방만 | 읽기 자문만 |
| `claude` | 자기 방만 | 읽기 자문만 |
| `codex-app` | 자기 방만 | `EXECUTION_AUTHORIZED`에서만 수정 |

같은 Windows 계정으로 실행하는 네 앱 사이의 역할 분리는 협력적
통제이며 강한 보안 경계는 아니다. 적대적 신원 분리가 필요하면 별도 OS
계정, 컨테이너, ACL 또는 adapter token이 필요하다.

## 화면별 설정

### Antigravity

1. 새 council 전용 Project를 만든다.
2. `C:\comunity`를 Add Folder한다.
3. 필요 시 제품 repo의 frozen/read-only snapshot을 추가한다.
4. Local Mode를 선택한다.
5. terminal auto execution은 전체 허용보다 coordinator 명령 allowlist를
   우선한다.

### Cursor

1. 새 council 전용 workspace에서 `C:\comunity`를 연다.
2. `.cursor\rules\four-agent-ensemble.mdc`가 활성화됐는지 확인한다.
3. Cursor는 advisor이므로 제품 코드를 수정하지 않는다.
4. Auto-review 또는 allowlist를 사용하더라도 Shell, MCP, Fetch 범위를
   council 명령으로 제한한다.
5. Cursor cloud/background agent는 원격 GitHub clone에서 실행되므로 이
   로컬 버스와 동일하지 않다.

### Codex App

1. `C:\comunity`를 local project로 연다.
2. `CODEX.md`, `AGENTS.md`를 읽게 한다.
3. R1/R2 동안 codex-app inbox가 빈 것은 정상이다.
4. scheduled wake를 쓸 수 있지만 PC와 앱을 켜 두어야 하고 local project
   범위가 유지돼야 한다.

### Claude

캡처의 일반 `claude.ai/chat`은 local bus 방이 아니다.

권장 순서:

1. Claude Code 또는 최신 Claude Desktop Cowork를 설치·인증한다.
2. `C:\comunity`를 local project/folder로 연다.
3. Remote Control을 사용하는 경우 `C:\comunity`에서
   `claude remote-control --name "Comunity Claude Advisor"`를 실행한다.
4. 일반 chat URL이 아니라 `claude.ai/code`의 해당 세션을 연다.
5. 첫 프롬프트에서 `C:\comunity\CLAUDE.md`를 직접 읽도록 시험한다.

이 direct-read 시험이 실패하면 Claude를 quorum에 포함하지 않는다.
파일 업로드는 live local bus가 아니다.

## 정상적인 idle

- task 생성 전: 모든 advisor `QUEUE_EMPTY`
- R1/R2: Codex App `WAITING_FOR_ADVISORS`
- plan/implementation 대기: advisor `QUEUE_EMPTY`
- quorum 미달: coordinator가 한 번 retry한 뒤 단일 approval packet

idle을 실패로 오인해 다른 agent의 결과를 대신 쓰면 안 된다.

## 앱이 해야 할 한 사이클

1. `room.ps1 next -Agent <id>`로 pending envelope 하나를 선택한다.
2. envelope의 Required context만 읽는다.
3. 정확한 `output_path`에 UTF-8 Markdown 새 파일을 쓴다.
4. `room.ps1 submit -Agent <id> -MessagePath <path>`를 실행한다.
5. `room.ps1 wait`로 다음 phase를 기다리거나 정상 종료한다.

inbox Markdown은 제출 후 남아 있으므로 파일 날짜만 보고 선택하면 안
된다. `room.ps1`은 대응하는 `messages\pending\<message-id>.json`이
존재하는 메시지만 선택한다.

## 검토 산출물 형식

plan review와 post review는 마지막에 다음 세 필드를 정확히 둔다.

```text
vote: APPROVE
hard_stop: NONE
evidence: 검증한 파일, SHA, 테스트 또는 구체적 근거
```

허용된 vote와 hard-stop code는 `AGENTS.md`와
`ensemble\POLICY.md`에 정의되어 있다.

## 완전 무인으로 전환하기 전

- target의 실제 detached/read-only snapshot 또는 isolated worktree
- 각 제품의 supported wake adapter
- envelope input/role/policy SHA binding
- normalized result schema validation
- atomic claim/collect와 cancel ownership

이 항목이 검증되기 전에는 GUI smoke loop를 완전 자율 시스템이라고
표현하지 않는다.
