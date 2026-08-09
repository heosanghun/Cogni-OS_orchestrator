# Cogni-OS Phase 1~11 실행계획

## 1. 완료의 정의

Cogni-OS에서 `완료`는 작업자가 작성한 `passed`, 예상값과 관측값이 같은
known-answer 항목, 테스트 프로세스의 종료 코드만으로 선언하지 않는다. 각 Phase의
고정 요구사항마다 다음 증거가 모두 있어야 한다.

1. 현재 릴리스와 정확히 같은 40자리 Git 커밋
2. 서명 원장과 독립 검증 번들로 확인된 `verified` 또는 `archived` 작업
3. Codex가 미리 고정한 canonical unittest 선택자의 trusted-runner 실행 기록
4. 타임아웃·출력 절단 없이 종료 코드 0으로 끝난 원시 출력과 SHA-256
5. 실제 파일을 다시 해시하여 확인한 요구사항별 산출물 SHA-256
6. 동일 Phase 및 다른 Phase에서 재사용되지 않은 고유 증거

`src/cogni_os/phase_evidence.py`의 결과는 **의미 증거 범위**만 판정한다. 결과가
`SEMANTIC_COVERAGE_PASS`여도 릴리스 권한은 항상 `false`이다. 설치 파일, 재시작,
GPU, 오프라인, 운영 D1/Pages까지 별도의 릴리스 게이트를 모두 통과해야 최종 완료가
된다.

```powershell
python scripts\audit_phase_evidence.py --workspace C:\comunity
```

- 종료 코드 `0`: 11개 Phase의 의미 증거 범위 통과(릴리스 승인이 아님)
- 종료 코드 `1`: 증거 누락·불일치·재사용에 따른 `NO_GO`
- 종료 코드 `2`: 입력 인벤토리·JSON·Git·파일 안전성 오류

레거시 P01~P11이 같은 `PASSED_ALL_TESTS` 원시 출력 또는 작업자 자기기입식
known-answer를 공유한 경우, 기존 상태가 `verified`여도 새 의미 증거 감사에서는
완료로 인정하지 않는다. 각 Phase는 canonical acceptance test로 다시 발급해야 한다.

## 2. 운영 원칙

1. Codex는 목표, 허용 기준, 권한, 증거, 중단 조건과 테스트 선택자를 먼저 고정한다.
2. Antigravity 수행자는 허용 범위에서 구현하고 산출물과 실행 증거를 제출한다.
3. 독립 검증자는 수행자 보고서를 정답으로 사용하지 않고 trusted runner로 재실행한다.
4. 같은 모델 계열의 자기평가만으로 승인하지 않으며, 서명 원장과 결정론적 검사를 함께 사용한다.
5. 연구실 GPU는 0~5만 허용하고 GPU 6·7은 탐지 즉시 `NO_GO`로 처리한다.
6. 원장, 서명, 원시 출력, 보고서, 재현 명령과 롤백 기록은 덮어쓰거나 삭제하지 않는다.
7. 실시간 관제는 최신 서명, nonce, D1 저장, 배포 커밋 중 하나라도 검증되지 않으면
   `LIVE`나 완료율을 표시하지 않는다.

## 3. Phase별 목표와 canonical 증거

| ID | 목표 | 반드시 독립 검증할 내용 |
|---|---|---|
| P01-TRUTH | 릴리스 진실성 기준선 | 현재 커밋, 원장 투영, 배포 귀속, 롤백 |
| P02-ORCHESTRATION | Codex+Antigravity 오케스트레이션 | 격리 runner, 서명 ingest, GPU 0~5, 재시작 복구 |
| P03-EVIDENCE | Evidence Kernel | 타입화 capsule, 누락 시 NO_GO, replay/rollback provenance |
| P04-WORLD | ESTC World Kernel | 전이 제약, 결정론적 재현, 사람 에스컬레이션·롤백 |
| P05-FINANCE | 금융투자 대표 World Pack | point-in-time, paper execution 대사, 위험 한도 정답 시험 |
| P06-TWIN | Agentic Twin 검증장 | golden replay, fault injection, poisoning 탐지 |
| P07-WORKSPACE | 로컬 Agent Workspace | 대화 종료, RAG·첨부·음성 계약, 도구 취소·복구 |
| P08-CORE | Gemma+DEQ+System 1.5/2.5/3/4 | 수렴, RTX 4090 VRAM·속도·품질, FWP/PLE 라우터 안전성 |
| P09-HARNESS | 통제형 Self-Harness | 주·야간 배타성, 격리 canary, 서명 rollback |
| P10-COGNIBOARD | 증거 중심 운영 UX | 서명 LIVE snapshot, fail-closed 표시, replay·rollback 조작 |
| P11-RELEASE | Appliance POC 릴리스 | RTX 4090 30회 재현, 외부 통신 0, 설치·재시작, 3도메인 replay |

## 4. P08 FWP→PLE 설계의 검증 가능한 형태

System 1.5의 DEQ 결과 `z*`를 저랭크 `Delta W`로 주입하는 기준선과, 층별
직관 레코드로 저장한 뒤 라우팅·검색·주입하는 `FWP+PLE` 후보를 같은 조건에서
비교한다. 현재 단계에서 PLE는 성능 사실이 아니라 다음 가설이다.

Gemma 4 E2B/E4B의 공식 PLE는 각 토큰에 대해 디코더 층별로 학습되어 모델과 함께
배포되는 정적 임베딩 테이블이다. 공식 문서가 `z*`를 런타임에 새 행으로 append하는
쓰기 가능한 기억 사전을 제공한다고 설명하는 것은 아니다. 따라서 Cogni-OS의
`FWP+PLE`는 기존 PLE를 그대로 사용하는 기능이 아니라, 공식 PLE의 층별 lookup
원리를 확장하는 별도 연구 어댑터로 명확히 구분하고 검증한다.

권장 PoC 데이터 흐름은 다음과 같다.

```text
DEQ z* -> LayerwiseIntuitionProgrammer -> C_session[layers, ple_dim]
                                      -> bounded sidecar bank
query -> confidence/OOD router -> 한 개 코드 lookup -> per-layer 임시 주입
                                                   -> 요청 종료 후 제거
```

Gemma 네이티브 PLE weight, tokenizer와 LM head는 수정하지 않는다. E4B 후보에서
검사된 42층×256차원 형상을 코드 계약으로 직접 하드코딩하지 않고, 서명된 모델
config에서 읽어 모델·tokenizer·checkpoint digest와 함께 저장한다. 첫 단계는 BF16,
최대 16개 세션, 명시적 byte limit, 한 요청에 한 코드로 제한한다. 복수 코드 합성,
3-bit/TurboQuant, 실제 채팅 logits 연결은 각각 독립 게이트를 통과한 뒤에만 연다.

필수 known-answer에는 zero-code stock equivalence, base/PLE weight 불변, digest가 다른
코드의 로드 거부, NaN/Inf·shape·dtype 거부, 결정적 LRU eviction, OOD fallback,
외부 held-out 품질 admission, 모든 생성 step과 대상 층의 적용 횟수, 요청 후 상태 제거를
포함한다. 첫 PoC는 현재 채팅 경로에 연결하지 않고 별도 opt-in validator에서만 실행한다.

| 주장 | 그대로 선언하지 않는 이유 | 실제 판정 지표 |
|---|---|---|
| 연산량 0 | 검색, 라우팅, 메모리 이동, 층별 주입에도 비용이 든다 | TTFT, token/s, GPU time, CPU time, energy proxy, lookup overhead |
| 충돌 완전 제거 | 잘못된 검색, 복수 직관 경쟁, 주입 위치 충돌이 남는다 | retrieval precision, collision rate, negative transfer, abstention |
| 용량 무한 확장 | 저장 공간, 인덱스 탐색, 캐시와 context 예산이 유한하다 | 레코드 수별 RAM/VRAM, p50/p95 lookup, 품질 열화 곡선 |
| 층별 정밀성 | 어느 층에 무엇을 주입할지 별도 학습·검증이 필요하다 | layer ablation, router entropy, task별 정확도, calibration |
| 배터리 비용 거의 0 | DRAM 접근과 라우팅도 전력을 사용한다 | 동일 장치·전력 모드의 energy/token 및 wall-clock |

P08 acceptance test는 최소한 다음 네 변형을 고정 데이터·고정 seed에서 비교한다.

1. Gemma 기준선
2. Gemma+DEQ 깊은 사고
3. Gemma+DEQ+FWP `Delta W`
4. Gemma+DEQ+FWP+PLE lookup/injection

모든 변형은 같은 프롬프트, 최대 토큰, 정지 조건, dtype, quantization, 장치에서
평가하며 warm-up과 측정 구간을 분리한다. 각 30회 실행의 원시 로그, VRAM peak,
지연시간, 품질, 반복·중단률, 검색 hit/miss, fallback 및 OOM을 보존한다. 평균 하나만
제시하지 않고 p50/p95와 실패 건수를 함께 기록한다.

PLE 항목은 immutable key, 모델·토크나이저·레이어 서명, 생성한 `z*` 영수증,
source commit, 데이터 계보, 양자화 방식, TTL/폐기 정책을 포함한다. 라우터 신뢰도가
낮거나 모델 서명이 다르거나 품질 회귀가 감지되면 PLE를 주입하지 않고 기준선으로
fail-closed fallback한다. 사용자 입력으로 임의 가중치나 PLE 파일을 직접 선택하지
못하게 한다.

## 5. 실시간 관제 계약

publisher는 원장의 신뢰 투영으로 `P01-TRUTH`부터 `P11-RELEASE`까지의 상태를
재계산하고 HMAC 서명 snapshot을 전송한다. 수신부는 다음을 다시 검사한다.

- 정확히 11개 canonical Phase인지
- 각 Phase 상태가 서명 원장 투영과 일치하는지
- `trusted_complete`가 현재 릴리스에서 다시 검증된 Phase 수인지
- 완료율이 `trusted_complete / 11`로 계산됐는지
- 순서, source commit, nonce, 타임스탬프와 서명이 유효한지

대시보드는 저장된 검증 snapshot을 주기적으로 다시 읽는다. 서명, 신선도, D1,
배포 커밋 또는 계약 검증 중 하나라도 실패하면 완료율을 숨기고 `NO_GO`를 표시한다.
로컬 테스트 통과와 Cloudflare 운영 배포 정상은 서로 다른 완료 조건이다.

## 6. 최종 릴리스 순서

1. 각 Phase canonical acceptance test 구현
2. 수행자 제출과 독립 trusted-runner 재실행
3. Phase 의미 증거 감사 11/11
4. 깨끗한 현재 커밋에서 전체 Python·JavaScript 회귀 테스트
5. RTX 4090에서 P08/P11 자원·품질·30회 재현 시험
6. 설치 파일 더블클릭, 재시작, 중단 복구, 롤백 시험
7. Cloudflare Pages·Functions·D1·secret·서명 snapshot 운영 검증
8. 금융 대표 World Pack과 바이오·국방 전환 replay 증거 검증

어느 단계에서든 미측정, 누락, skip, 서명 불일치, 재사용 또는 외부 통신이 발견되면
최종 상태는 완료가 아니라 `NO_GO`이다.
