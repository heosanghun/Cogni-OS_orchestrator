# Cogni-OS Phase 1~11 실행계획

이 문서는 구현 순서를 설명하는 일정표가 아니라, `VERIFIED` 또는
`ARCHIVED` 증거가 있어야 다음 단계가 열리는 실행 계약입니다.

## 운영 원칙

1. Codex가 목표, 수용 기준, 권한, 증거, 중단 조건을 고정합니다.
2. Antigravity는 허용된 범위에서 구현하고 `SUBMITTED` 증거를 냅니다.
3. Codex는 제출물을 재사용하지 않고 trusted runner로 재실행합니다.
4. 같은 Antigravity 모델 계열의 별도 이름은 독립 검증으로 인정하지 않습니다.
5. GPU는 0~5만 허용하고 6·7은 모든 단계에서 거절합니다.
6. 원장·태스크·제출·보고 이력은 수정하거나 삭제하지 않습니다.
7. 실시간 관제는 서명·신선도·저장소 검증 실패 시 `NO_GO`입니다.

## 등록과 조회

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m cogni_os.cli roadmap bootstrap C:\comunity `
  --actor codex `
  --owner antigravity

python -m cogni_os.cli roadmap status C:\comunity
```

등록 명령은 멱등적입니다. 동일 ID의 계약이 이미 존재하면 그대로 사용하지만,
제목·설명·권한·게이트 등이 바뀌어 있으면 조용히 덮어쓰지 않고 실패합니다.

## 단계

| ID | 단계 | 핵심 게이트 |
|---|---|---|
| P01-TRUTH | 릴리스 진실성 기준선 | 저장소·원장·배포·신원 정합성 |
| P02-ORCHESTRATION | 신뢰 오케스트레이션과 실시간 증거 | 서명된 snapshot, 재부팅 복구, GPU 0~5 |
| P03-EVIDENCE | Evidence Kernel | 누락·skip·unmeasured 시 NO_GO |
| P04-WORLD | ESTC World Kernel | 금지 전이 커밋 0건 |
| P05-FINANCE | 금융투자 World Pack | point-in-time·대사·paper trading |
| P06-TWIN | Agentic Twin | 실패주입·정책우회·rollback |
| P07-WORKSPACE | 로컬 Agent Workspace | 대화·RAG·파일·음성·도구 회귀 |
| P08-CORE | Cogni-Core 실측 통합 | CTS→1.5→2.5→3→4, GPU 0~5 |
| P09-HARNESS | 통제된 Self-Harness | 운영 직접 수정 0건 |
| P10-COGNIBOARD | 증거 관제 UX | 미검증 LIVE 표시 0건 |
| P11-RELEASE | Appliance POC 릴리스 | 30회 재현·재부팅·rollback·오프라인 |

진행률은 `P01`~`P11` 중 `verified` 또는 `archived` 상태의 개수만으로
계산합니다. 일반 태스크 수, 에이전트의 자기 보고, 실행 시간 추정치는
진행률에 포함하지 않습니다.

## 실시간 관제 데이터 계약

publisher는 신뢰 상태로 정규화된 태스크에서 `roadmap` 객체를 생성하고,
HMAC 서명 대상 snapshot 안에 포함합니다. Cloudflare 수신부는 다음을 모두
다시 계산해 일치할 때만 저장합니다.

- 정확히 `P01-TRUTH`부터 `P11-RELEASE`까지 11개인지
- 각 Phase의 상태가 같은 snapshot의 태스크 상태와 일치하는지
- `trusted_complete`가 `verified` 또는 `archived`인 Phase 수와 같은지
- `progress_percent`가 `trusted_complete / 11`에서 계산되었는지
- 선행 단계가 고정된 순서와 일치하는지

대시보드는 `/api/snapshot`을 5초마다 다시 읽습니다. 서명, 신선도, D1
저장소 또는 위 계약 중 하나라도 실패하면 Phase 진행률을 숨기고
`NO_GO`를 표시합니다. 따라서 아직 검증되지 않은 단계나 단순 자기 보고가
진행률을 올릴 수 없습니다.
