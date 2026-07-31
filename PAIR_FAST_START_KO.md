# Antigravity + Codex App 빠른 로컬 대화

이 경로는 두 에이전트가 사용자의 복사·붙여넣기 없이 로컬 파일로
대화하는 **읽기 전용 `PAIR_WORKBENCH`**입니다.

> Antigravity의 추가 역할 라벨은 같은 모델 계열이므로 독립 검증자가
> 아닙니다. `PAIR_CANDIDATE`는 계획 후보일 뿐이며 제품 코드 수정,
> Git push, 배포 또는 task plane의 `verified`를 허가하지 않습니다.

## 실제 연결 구조

```text
Codex/brief
  -> SHA 고정 Antigravity language_server + agentapi (R1 비동기 전송)
  -> Antigravity 전용 outbox -> broker-only 원자 격리/검증
  -> SHA 고정 Codex 비대화형 read-only worker (초안)
  -> 같은 Antigravity 대화 (R2 비동기 전송·격리·검증)
  -> Codex read-only worker (PAIR_CANDIDATE)
```

- 전송 감지는 `.NET FileSystemWatcher`가 담당합니다.
- 3초 전수 스캔은 watcher 이벤트 유실 복구용입니다.
- Codex 실행 프로세스와 각 adapter의 로컬 runner/CLI 자손은 gated
  Windows Job Object 안에서 실행됩니다. 브로커 종료·로컬 호출 제한시간
  초과·중단 요청 시 이 로컬 프로세스 트리는 함께 종료됩니다.
- Antigravity `agentapi`는 서버측 대화를 비동기로 전송하며 공개 취소
  명령을 제공하지 않습니다. 따라서 Job 종료나 중단은 서버측 모델 생성을
  취소한다고 주장하지 않습니다. 중단·대기 만료는 broker의 **결과 수락
  권한을 철회**하며, 이후 outbox 결과는 canonical 결과로 승격하지 않습니다.
- 공개 완료 API가 없으므로 production Sidecar는 브로커가 직접 계산한
  DONE/응답의 SHA·크기가 최소 두 번의 reconcile과 30초 동안 같을 때만
  라운드 디렉터리를 격리합니다. 에이전트가 바꿀 수 있는 파일 작성시각은
  신뢰하지 않습니다. 이는 “완료 취소” 보장이 아니라 조기 DONE/후속
  재작성의 수락을 막는 안정화 창입니다.
- 실제 Antigravity `language_server.exe`, Codex, Git, runner의 절대경로와
  SHA-256을 호출 직전마다 다시 검증합니다. 프로그램 업데이트로 SHA가
  달라지면 자동 재승인하지 않고 시작 전에 중단합니다.
- 외부 호출 직전 상태를 `RUNNING_ANTIGRAVITY_*` 또는
  `RUNNING_CODEX_*`로 먼저 기록합니다. 브로커가 비정상 종료되면 같은
  attempt를 재호출하지 않고 새 증거와 함께 `PAIR_SAFE_STOP`으로 닫습니다.
- 파일 전송은 대체로 즉시지만 전체 왕복 시간은 모델 추론 시간이
  지배하므로 1초 완료를 보장하지 않습니다.
- pair task 생성만으로 모델이나 GUI가 깨어나지 않습니다. pin과 권한
  검증을 통과한 `pair-sidecar.ps1`이 실제 adapter를 호출합니다.

## 태스크 만들기

```powershell
$TaskId = (
  powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File C:\comunity\orchestrator\pair.ps1 new-task `
    -WorkspaceRoot C:\comunity `
    -Title "Stage 2 완료 증거 독립 검증" `
    -Goal "체크포인트 SHA, 완료 로그, 프로세스 상태와 다음 단계 계획을 읽기 전용으로 검증" `
    -TargetWorkspace C:\Project\System1.5
).Trim()

powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\pair.ps1 status `
  -WorkspaceRoot C:\comunity `
  -TaskId $TaskId
```

정상 종착점은 `PAIR_CANDIDATE`, 안전 중단은 `PAIR_SAFE_STOP`입니다.
응답과 SHA sidecar는 다음 경로에 보존됩니다.

```text
C:\comunity\.ensemble-runtime\pair-workbench\tasks\<PAIR-ID>\
C:\comunity\.ensemble-runtime\pair-agent-outbox\<PAIR-ID>\
```

Codex 또는 로컬 dispatch CLI가 실행 중이어도 lock 획득을 기다리지 않고
중단 요청을 남길 수 있습니다. 로컬 runner는 최대 250ms 주기로 요청을
확인합니다. Antigravity 결과 대기 중에는 다음 reconcile과 최종 승격 직전
요청을 확인해 수락을 철회하지만 서버측 생성 자체는 취소하지 않습니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File C:\comunity\orchestrator\pair.ps1 stop `
  -WorkspaceRoot C:\comunity `
  -TaskId $TaskId `
  -Reason "사용자 중단"
```

## 권한 창을 반복하지 않는 원칙

- Antigravity는 전용 `Comunity Pair Broker` 프로젝트에서 동작합니다.
  유일한 쓰기 허용 범위는
  `C:\comunity\.ensemble-runtime\pair-agent-outbox`입니다.
  `pair-workbench`의 STATE·락·프롬프트·attempt·검증 증거와
  `C:\Project\System1.5`, orchestrator, tests에는 write deny가 적용됩니다.
- Codex worker는 `read-only` sandbox와 `approval_policy="never"`를
  사용합니다.
- Sidecar는 승인 우회가 아니라 위의 좁은 고정 권한만 사용합니다.
- broad/yolo/bypass 권한은 사용하지 않습니다.
- 권한 부족은 `PAIR_SAFE_STOP`에 한 번 기록하며 같은 상태에서 다시
  사용자에게 묻지 않습니다.

Antigravity/Codex/Git/runner가 업데이트되면 SHA mismatch로 fail-closed
됩니다. 새 바이너리를 검증한 뒤 Sidecar manifest의 pin을 의도적으로
갱신해야 하며, 자동으로 새 실행체를 신뢰하지 않습니다.

## 증거와 보장 범위

- 각 로컬 호출의 `.attempts\<INVOCATION-ID>\` 아래에 process spec,
  RUNNING, RESULT, 원본 로그·응답, `INVOCATION_EVIDENCE.json`과 SHA
  sidecar가 남습니다. 검증된 복사본만 task 최종 경로로 승격됩니다.
- Antigravity가 완료한 라운드 디렉터리는 writable outbox에서
  broker-only `.antigravity-imports\<R1|R2>`로 원자 이동한 뒤 다시
  경로·reparse·크기·DONE SHA·front matter를 검증합니다. 원본과 import
  evidence는 보존되고, broker가 정규화한 복사본만 최종 경로에 게시됩니다.
- 수락된 각 라운드는 broker-only `.antigravity-seals\<R1|R2>.json`에
  canonical/import SHA로 봉인됩니다. 이후 reconcile과 `PAIR_CANDIDATE`
  이후에도 같은 writable 라운드가 다시 나타나면 별도 late-result 증거로
  격리하고 후보를 `PAIR_SAFE_STOP`으로 무효화합니다.
- `PAIR_CANDIDATE.md`, 그 DONE, Codex R1 산출물도
  `PAIR_CANDIDATE_SEAL.json`에 묶여 terminal reconcile마다 재검증됩니다.
  SAFE_STOP 증거와 raw Antigravity import도 SHA·sidecar·정확한 파일
  manifest를 다시 확인하므로 삭제·변조를 조용히 통과시키지 않습니다.
- 대상 Git snapshot은 HEAD, porcelain status, tracked binary diff,
  untracked 파일 SHA를 비교합니다. 이 fingerprint는 보조 증거이며,
  실제 쓰기 차단의 1차 경계는 Antigravity 프로젝트 write deny와 Codex
  read-only sandbox입니다.
- `PAIR_CANDIDATE`는 두 모델의 읽기 전용 계획 후보입니다. 제품 수정,
  학습 시작, Git commit/push 또는 task plane의 `verified`를 의미하지
  않습니다.

## 공식 실행 파일

공식 pair 경로는 `orchestrator\pair.ps1`,
`orchestrator\pair-process-runner.ps1`,
`orchestrator\pair-sidecar.ps1` 세 파일뿐입니다.
