# Cogni-OS Codex–Antigravity 거버넌스

## 1. 목적

Cogni-OS는 모델의 자기 보고가 아니라 실행 가능한 테스트, 원본 로그,
SHA-256 manifest, 서명된 원장과 재현 명령으로 완료를 판정합니다.
현재 협업 토폴로지는 Codex 지휘자와 Antigravity 수행자/자문자로
한정합니다.

## 2. 역할

### Codex

- 목표와 완료 조건을 원자적 task로 분해
- 최소 권한, write root, GPU 0~5, 네트워크 게이트 설정
- 수행 증거와 분리된 known-answer 재현
- `accept`/`reject`, release gate와 공개 주장에 대한 최종 책임

### Antigravity

- lease를 가진 task만 실행
- 허용된 write root 안에서 구현·회귀 검사
- 보고서와 재현 가능한 evidence manifest 제출
- pair workbench에서는 읽기 전용 R1/R2 자문 제공

### 같은 모델 계열의 추가 역할

`antigravity-verifier`는 이름과 control principal이 달라도
`google-antigravity` 수행자와 같은 canonical model family입니다.
따라서 Antigravity가 제출한 결과의 독립 검증 요건을 충족하지 않습니다.
Python `evaluate_independence`가 `same_model_family`로 거절하며, Codex가
별도 검증 evidence를 생성해 책임 판정합니다.

## 3. 신뢰 판정

```text
worker submission
  → manifest 구조·hash·권한 검사
  → trusted runner가 known-answer 재실행
  → Codex가 별도 verifier manifest 생성
  → identity independence 검사
  → accept/reject 원장 기록
```

독립성 검사는 다음 중 하나라도 겹치면 실패합니다.

- actor
- control principal
- canonical model family
- alias lineage
- worker와 동일한 evidence manifest

## 4. 운영 평면

### Python task plane

공식 상태 변경 경로는 `cogni` CLI입니다.

```powershell
cogni task add <workspace> --actor codex ...
cogni task claim <workspace> --actor antigravity ...
cogni task start <workspace> --actor antigravity ...
cogni task submit <workspace> --actor antigravity ...
cogni task verify <workspace> --actor codex ...
```

### Pair workbench

`orchestrator/pair.ps1`, `pair-process-runner.ps1`,
`pair-sidecar.ps1`은 고정된 Git snapshot을 대상으로 읽기 전용 분석을
수행합니다. 성공 종착점 `PAIR_CANDIDATE`는 계획 후보일 뿐 상태 변경이나
릴리스 권한이 아닙니다.

## 5. 불변 증거

다음 디렉터리의 기존 파일은 역사 기록이므로 수정·삭제하지 않습니다.

- `ledger/`
- `tasks/`
- `submissions/`
- `reports/`

과거 주장이 현재 코드와 다르면 역사를 고쳐 쓰지 않고 새 감사 이벤트와
새 재현 증거로 교정합니다.

## 6. 완료 기준

task를 완료라고 부르려면 최소한 다음이 필요합니다.

1. 명시된 범위의 변경
2. 실행한 정확한 테스트 명령과 종료 코드
3. 원본 출력 또는 hash가 포함된 증거
4. dirty tree와 사용자 변경 보존 확인
5. 독립성 판정 통과
6. GPU·네트워크·secret·배포 경계 위반 없음

미실행 검사는 `PASS`로 추정하지 않습니다.
