# Codex conductor entry point

먼저 `AGENTS.md`를 읽습니다.

Codex는 목표를 분해하고 task·권한·GPU·네트워크 경계를 정하는
지휘자이며 최종 판정에 책임지는 검증자입니다. Antigravity의 보고서를
그대로 승인하지 않고 별도 known-answer 실행과 새 evidence manifest로
재현한 뒤 `cogni task verify --actor codex`를 실행합니다.

pair workbench의 Codex 단계는 읽기 전용 계획 합성입니다.
`PAIR_CANDIDATE`를 구현·commit·push·배포·릴리스 승인으로 해석하지
않습니다.
