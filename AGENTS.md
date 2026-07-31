# Codex–Antigravity 운영 규칙

이 저장소의 현재 운영 경로는 Python `cogni` CLI와
`orchestrator/pair*.ps1`뿐이다. 삭제된 다중 자문 council 경로를
복원하거나 우회 진입점으로 사용하지 않는다.

## 책임 분리

- **Codex**는 지휘자이자 책임 검증자다. 목표 분해, 권한 경계,
  독립 재현, 최종 accept/reject 및 릴리스 판정을 책임진다.
- **Antigravity**는 수행자 또는 자문자다. 할당된 쓰기 범위 안에서
  구현·테스트·증거 제출을 수행한다.
- `antigravity-verifier`라는 역할 라벨은 별도 신뢰 주체를 만들지
  않는다. `google-antigravity` 계열 수행자와 같은 모델 계열이므로
  그 수행 결과에 대한 독립 검증 요건을 충족하지 못한다.
- Python 신뢰 게이트는 actor 이름이 아니라 control principal,
  canonical model family, alias lineage와 별도 증거를 검사한다.

## 두 운영 평면

1. **Task plane**: `cogni task add/claim/start/submit/verify`와 서명된
   append-only 원장을 사용한다. Antigravity가 제출한 작업의 최종
   검증 actor는 재현 증거를 새로 만든 Codex다.
2. **Pair workbench**: `orchestrator/pair.ps1`,
   `pair-process-runner.ps1`, `pair-sidecar.ps1`의 읽기 전용 분석
   라운드다. 종착점 `PAIR_CANDIDATE`는 계획 후보이며 제품 수정,
   commit, push, 배포 또는 릴리스 승인이 아니다.

## 절대 규칙

1. `ledger/`, `tasks/`, `submissions/`, `reports/`의 기존 역사 증거는
   수정·삭제·재작성하지 않는다.
2. 사용자 변경을 보존한다. reset, discard checkout, force push,
   자동 rebase, 파괴적 정리를 사용하지 않는다.
3. 완료 주장은 테스트 명령, 종료 코드, 원본 로그, SHA-256과 재현
   명령으로 입증한다. 역할 이름이나 에이전트 자기 보고는 증거가 아니다.
4. 동일 모델 계열의 자기 검토를 독립 검증으로 승격하지 않는다.
5. GPU 사용은 0~5만 허용하고 6·7은 사용하지 않는다.
6. secret, credential, 비용 발생, 공개 배포, destructive operation은
   명시적 외부 경계다. 같은 상태에서 사용자에게 승인 질문을 반복하지
   않고 하나의 fail-closed 기록으로 합친다.
7. 공개 관제는 검증된 운영 메타데이터의 읽기 전용 투영이다. 데이터가
   없거나 서명·신선도 검증에 실패하면 `LIVE`를 표시하지 않는다.

## 시작 순서

1. `README.md`와 `START_HERE_KO.md`를 읽는다.
2. `cogni doctor <workspace>`로 원장·projection·역할 정합성을 확인한다.
3. pair 분석이 필요하면 `PAIR_FAST_START_KO.md`를 읽고 `pair.ps1
   probe`를 먼저 실행한다.
4. 변경 후 Python tests, PowerShell pair test, Node monitoring tests 중
   변경 범위에 해당하는 검증을 실행하고 결과를 함께 보고한다.
