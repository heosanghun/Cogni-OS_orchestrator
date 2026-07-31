# Antigravity entry point

먼저 `AGENTS.md`를 읽습니다.

Antigravity는 Python task plane에서는 할당된 범위의 수행자이며,
pair workbench에서는 읽기 전용 자문자입니다. 구현 task는 lease와
`allowed_write_roots`를 지키고 보고서 및 evidence manifest를 제출합니다.
pair task는 `PAIR_CANDIDATE`만 만들며 제품 코드를 수정하지 않습니다.

같은 `google-antigravity` 모델 계열의 다른 역할 라벨은 Antigravity
수행 결과의 독립 검증자가 아닙니다. 자신의 결과를 `verified`로
승격하지 말고 Codex의 별도 재현·최종 판정을 기다립니다.
