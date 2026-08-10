# Monitoring production recovery 보안 계약

`monitoring-production-recovery.yml`은 Cloudflare 운영 상태를 두 개의 서로 다른
판정으로 분리한다.

1. `recover-platform`: D1 migration과 Pages main 배포를 거쳐 **플랫폼이
   `CONFIGURED`인지** 확인한다.
2. `verify-live`: 이 워크플로 밖의 신뢰 게시자가 이미 게시한 snapshot이 서명,
   freshness, source commit, 고유 Pages deployment 및 저장 이력까지 충족하는지
   **읽기 전용으로** 검증한다.

`recover-platform` 성공은 signed `LIVE` 성공이 아니다. 복구 job에는
`INGEST_HMAC_KEYS`, publisher signing key 또는 `/api/ingest` 호출이 없으며 이를
추가해서도 안 된다. 별도 게시자와 별도 `verify-live` 실행 전까지 제품 및 Phase
완료 판정은 `NO_GO`다.

dispatch의 기본 선택은 원격 변경이 없는 `verify-live`다. D1과 Pages를 변경하는
`recover-platform`은 운영자가 명시적으로 선택하고 보호 environment 검토를
통과해야만 실행된다.

## Phase 1~11 의미 증거 감사

`source-validation`은 의존성 설치보다 먼저 `audit_phase_evidence.py`를 실행한다.
감사 종료 코드 `0`은 11개 Phase의 의미 증거가 모두 충족된 상태이고, 종료 코드 `1`은
정상적인 `NO_GO` 진행 상태다. 구조 오류, 감사 정책 오염 또는 읽기 실패를 뜻하는 종료 코드
`2`는 워크플로를 즉시 중단한다. 결과 JSON은 별도 artifact로 봉인하지만
`release_authority`는 항상 `false`이므로 이 감사만으로 배포나 릴리스 승인을 주장할 수 없다.

운영 `LIVE` 판정은 이 로컬 감사와 별개로 외부 publisher가 서명한 동일 감사 결과, D1에
저장된 원문 본문 해시, 현재 Pages 배포, 독립 release gate 및 최신 history 행이 모두
교차 결합된 경우에만 가능하다.

## GitHub production environment의 외부 필수 설정

YAML은 `monitoring-production` environment를 참조하지만 보호 규칙 자체는 GitHub
저장소 설정에 존재한다. 운영자가 다음 규칙을 모두 구성한 후에만 environment
variable을 설정한다.

- environment 이름: `monitoring-production`
- required reviewer: 수행자와 다른 독립 검증자 또는 팀
- prevent self-review: 활성화
- deployment branch: 보호된 `main`만 허용
- administrator bypass: 비활성화
- environment variable:
  `COGNI_MONITORING_PRODUCTION_POLICY=required-reviewer+prevent-self-review+main-only+no-admin-bypass-v1`
- environment variable: 32자리 소문자 account ID인 `CLOUDFLARE_ACCOUNT_ID`
- environment secret: bookmark와 migration 목록만 조회할 수 있는 **D1 Read 전용**
  `CLOUDFLARE_D1_READ_TOKEN`
- environment secret: migration에만 사용하는 **D1 Edit 전용**
  `CLOUDFLARE_API_TOKEN`, 동일 account를 나타내는 기존 계약의
  `CLOUDFLARE_ACCOUNT_ID`, main 전용 `CLOUDFLARE_PAGES_DEPLOY_HOOK`

읽기 전용 variable account ID와 migration secret account ID는 SHA-256으로
비교하며 서로 다르면 mutation 전에 실패한다. Cloudflare 공식 permission 정의에서
`D1 Read`와 `D1 Edit`는 별도 account permission이다.

- Cloudflare API token permissions:
  <https://developers.cloudflare.com/fundamentals/api/reference/permissions/>

워크플로는 `GITHUB_REF_PROTECTED=true`, 정확한 main ref 및 위 policy marker가
없으면 D1 변경 전에 실패한다. marker는 GitHub 설정을 암호학적으로 증명하지
않으므로 required reviewer, self-review 방지, branch policy, bypass 방지는 별도의
저장소 설정 감사 대상이다. GitHub 공식 문서에 따르면 environment secret은 해당
environment의 보호 규칙이 통과되기 전에는 job에 제공되지 않는다.

- GitHub environments 및 보호 규칙:
  <https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments>
- deployment 검토 및 self-approval 방지:
  <https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/review-deployments>

## D1 pre/post 증거와 비밀정보 경계

migration 직전과 직후에 다음 읽기 전용 상태를 캡처한다.

- `wrangler d1 time-travel info ... --json`이 반환한 bookmark의 SHA-256
- `wrangler d1 migrations list ... --remote` 출력의 SHA-256
- 출력에서 추출한 안전한 migration 파일명 목록
- source commit, GitHub run ID/attempt, 고정 Wrangler 버전
- pre 파일 SHA-256, 먼저 봉인한 artifact SHA-256, migration 실행 출력 SHA-256

post 목록에 적용되지 않은 migration 파일명이 하나라도 남으면 workflow는 Pages
deploy hook을 호출하기 전에 실패한다.

원본 bookmark, D1 행, migration 명령 원문 출력, API token 및 account credential은
artifact나 로그에 남기지 않는다. 임시 원문은 권한 `0700` 임시 디렉터리에서만
사용하고 각 secret-scoped step 종료 시 삭제한다. 첫 단계는 D1 Read 토큰으로 pre
receipt를 만들고 SHA-256을 계산한 뒤 읽기 전용(`0400`)으로 고정한다. 이 단계가
종료되어 read token이 더 이상 노출되지 않은 다음, pinned `upload-artifact` action이
pre receipt를 immutable archive로 **migration 전에 먼저 봉인**한다.

그 뒤의 별도 단계만 D1 Edit token을 받는다. 이 단계는 mutation 전에 로컬 pre 파일
SHA-256, 이미 봉인된 pre artifact digest, read/write account ID digest를 모두
검증한다. migration과 post capture가 끝난 뒤에도 pre 파일 SHA가 같은지 다시
검증한다. post receipt는 이미 반환된 pre artifact digest에 직접 결속된다.
pre와 post는 서로 다른 `actions/upload-artifact@v4.6.2` artifact로 봉인한다.
pre, post, configured probe 및 live probe artifact는
각각 고유한 run ID/attempt 이름과 `overwrite: false`, 90일 retention을 사용한다.
모든 action은 전체 commit SHA로 고정한다.

migration 직전에는 pre receipt 파일 SHA-256과 bookmark SHA-256만 Actions log에
먼저 기록하고, migration 이후에는 post receipt SHA-256과 pre artifact digest만
기록한다. 따라서 원본 bookmark나 D1 행을 노출하지 않으면서 명령 순서를 감사할 수
있다. workflow run 삭제 권한자는 이 로그도 삭제할 수 있으므로 독립 WORM 증거는
여전히 외부 필수 조건이다.

`upload-artifact` v4의 archive는 업로드 뒤 내용을 수정할 수 없고 새 artifact ID와
SHA-256 digest를 반환한다. 다만 write 권한자는 artifact나 run을 삭제할 수 있다는
한계는 그대로 유지한다.

- upload-artifact v4 immutability, digest 및 retention:
  <https://github.com/actions/upload-artifact/tree/v4.6.2>

GitHub artifact는 pre-mutation 순서를 증명하는 보존 기간 내 워크플로 증거이지만
WORM 또는 영구 규제 보관소를
대체하지 않는다. 삭제 권한이 있는 관리자는 artifact나 workflow run을 삭제할 수
있으므로, 릴리스 증거로 승격할 때는 독립 외부 보관소에 artifact digest와 GitHub
run URL을 추가 보존해야 한다.

## Time Travel 및 Pages rollback rehearsal의 의미

Cloudflare D1 migration apply는 CI에서도 확인 prompt 없이 수행되며 migration 전
backup을 생성한다. Time Travel은 production storage backend에서 bookmark 기반
복구를 제공하지만 restore는 데이터베이스를 제자리에서 덮어쓰는 파괴적 작업이다.
따라서 이 워크플로는 `d1 time-travel restore`를 실행하지 않는다.

대신 `recovery-rehearsal-receipt.json`에는 다음 사실만 기록한다.

- migration 직전·직후 bookmark의 **해시**가 관측됨
- migration 직전 UTC capture timestamp가 보존되어 별도 승인 절차에서 bookmark를
  다시 조회할 수 있음
- D1 restore mutation은 수행되지 않음
- 실제 restore에는 별도의 사고/change 승인과 undo bookmark 보존이 필요함
- Pages rollback mutation은 수행되지 않음
- Pages rollback target은 이전의 서로 다른 successful production deployment여야
  하며 preview deployment는 금지됨
- 현재 receipt는 `PROCEDURE_ONLY_NO_MUTATION`이며 실제 rollback 성공 증거가 아님

실제 장애 복구를 수행할 때는 보호된 별도 절차에서 원본 bookmark와 현재 undo
bookmark를 권한 분리해 보관하고, 복구 직후 새 bookmark와 API 응답을 다시
봉인해야 한다. Pages rollback 역시 Cloudflare API로 대상이 successful production
deployment인지 독립 확인한 후 별도 승인을 받아야 한다.

- Cloudflare D1 Time Travel 및 파괴적 restore 주의사항:
  <https://developers.cloudflare.com/d1/reference/time-travel/>
- Cloudflare D1 migrations:
  <https://developers.cloudflare.com/d1/reference/migrations/>
- Cloudflare Pages rollback 대상 제한:
  <https://developers.cloudflare.com/pages/configuration/rollbacks/>

## 로컬 재현

원격 mutation 없이 워크플로 계약과 로컬 migration만 검증한다.

```powershell
node --test tests/web/monitoring-recovery-workflow.test.mjs
python -I scripts/validate_monitoring_migrations.py
npm test
```

실제 `recover-platform` 실행 전 외부 필수 조건은 다음과 같다.

1. 위 GitHub environment 보호 규칙과 environment secrets/marker가 설정됨
2. Cloudflare token이 해당 D1 migration에 필요한 최소 권한만 가짐
3. D1이 Time Travel을 지원하는 production backend임
4. Pages project의 production branch와 deploy hook이 `main`에 결속됨
5. 외부 신뢰 publisher가 별도 호스트에서 schema 1.3 signed snapshot을 게시할 수 있음
6. `verify-live`가 현재 main commit과 고유 deployment를 대상으로 통과함
