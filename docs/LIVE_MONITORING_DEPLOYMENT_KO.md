# Cogni-OS 실시간 증거 관제 배포

## 판정 원칙

공개 화면은 운영 주장의 원본이 아닙니다. 화면은 다음 검증을 통과한
스냅샷만 `LIVE`로 표시하는 읽기 전용 투영입니다.

1. 로컬 원장 HMAC 체인 검증
2. outbound publisher의 HMAC-SHA256 V2 요청 서명
3. 허용된 `key_id`와 해당 키의 일치
4. 5분 이내 관측 시각
5. 재사용 불가 nonce
6. workspace별 단조 증가 sequence
7. D1에 저장된 본문 SHA-256
8. GPU 0~5 allowlist와 GPU 6·7 denylist
9. 최근 180초 이내 신선도

바인딩, 키링, 데이터 또는 신선도가 없으면 화면은 `UNCONFIGURED`,
`NO_DATA`, `STALE`, `CORRUPT` 중 하나를 표시합니다. 검증 실패를 정적
샘플 값이나 과거의 정상 수치로 대체하지 않습니다.

## HMAC V2 계약

Cloudflare에는 단일 비밀키 대신 encrypted secret
`INGEST_HMAC_KEYS`를 둡니다. 값은 다음 형태의 JSON object이며 한 번에
1~4개 키만 허용합니다.

```json
{
  "publisher-2026q3": "<32-256-char-random-secret>",
  "publisher-2026q4": "<32-256-char-random-secret>"
}
```

- `key_id`: `[A-Za-z0-9._:-]{3,64}`
- secret: 32~256자
- 실제 secret은 Git, `wrangler.toml`, 명령 이력, 로그, 보고서에 기록 금지
- 로컬 개발에서는 gitignore된 `.dev.vars` 또는 프로세스 환경 변수만 사용

publisher는 다음 문자열을 UTF-8로 만들고 HMAC-SHA256으로 서명합니다.

```text
COGNI-SNAPSHOT-V2
<key_id>
<workspace_id>
<sequence>
<observed_at>
<nonce>
<body_sha256>
```

각 줄 사이에는 LF(`\n`) 하나만 있습니다. 요청에는
`X-Cogni-Key-Id`, `X-Cogni-Workspace`, `X-Cogni-Sequence`,
`X-Cogni-Observed-At`, `X-Cogni-Nonce`, `X-Cogni-Signature` 헤더가
필수입니다. 알 수 없거나 제거된 `key_id`, 잘못된 서명, 재사용 nonce,
같거나 낮은 sequence는 모두 fail-closed로 거절됩니다.

HTTP `202` 자체는 게시 성공 증거가 아닙니다. publisher는 응답이 정확히
`{ok, accepted}` 두 필드로만 구성되고, `accepted`의
`workspace_id`, `sequence`, `observed_at`, `body_sha256`가 방금 전송한
스냅샷과 일치하며 `signature_verified=true`인지 검증합니다. 서버가 생성한
`received_at`은 정확한 `YYYY-MM-DDTHH:mm:ss.sssZ` 형식이어야 하며 로컬의 요청
시작·응답 수신 시간창(프로토콜 최대 시계 오차 300초)에 결합됩니다. 응답 헤더
`X-Cogni-Sequence`, `X-Cogni-Body-SHA256`도 같은 값이어야 합니다. 응답
스키마가 늘거나 줄거나, JSON member가 중복되거나, 값 하나라도 다르면 journal에
성공을 기록하지 않고 fail-closed로 실패합니다.

## 데이터 경계

publisher는 다음 운영 메타데이터만 외부 관제 채널에 전송합니다.

- task ID, 정식 Phase 공개 라벨, 담당 agent ID, 상태, 시각
- P01~P11의 신뢰 상태와 `trusted_complete / 11` 기반 진행률
- 검증 신뢰 상태와 원장 head hash
- 실행 주체의 공개 상태 및 attestation 여부
- GPU 0~5의 사용률·VRAM·온도·전력
- 시스템 메모리·디스크·load·uptime
- release gate 상태와 증거 SHA-256

프롬프트, 고객 데이터, 모델 입출력, 소스 내용, 환경 변수, 비밀키,
파일 내용, 제어 명령은 전송하지 않습니다. 공개 API는 Cogni-Core로
명령을 전달하는 경로를 제공하지 않습니다. 사용자가 입력한 task 제목·설명,
workspace 고객명, agent의 자유문장 현재 작업명도 공개 payload에 싣지 않습니다.

## Cloudflare D1 준비

실제 Cloudflare 계정에서 데이터베이스를 생성하고 반환된 실제 ID만
`wrangler.toml`의 `d1_databases` 블록에 입력합니다.
binding 이름은 반드시 `MONITOR_DB`여야 합니다.

```powershell
npx wrangler d1 create cogni-os-monitoring
npx wrangler d1 migrations list cogni-os-monitoring --remote
npx wrangler d1 migrations apply cogni-os-monitoring --remote
```

위 명령은 `migrations/0001_monitoring.sql`과
`migrations/0002_monitoring_schema_floor.sql`을 순서대로 적용합니다. protected
production 환경에서 이 단계와 아래 probe가 성공하기 전에는 Pages 함수를
배포하거나 publisher를 재시작하지 않습니다. 스키마 적용 뒤 `key_id` 열,
필수 index, schema floor 테이블을 확인합니다.

```powershell
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA table_info(monitor_snapshots);"
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA table_info(monitor_history);"
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA table_info(monitor_nonces);"
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA index_list(monitor_history);"
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA table_info(monitor_schema_floors);"
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "SELECT name FROM sqlite_schema WHERE name = 'monitor_schema_floors';"
```

`0001_monitoring.sql`은 신규 데이터베이스 기준입니다. 이미 V1 테이블이
존재한다면 `CREATE TABLE IF NOT EXISTS`는 `key_id` 열을 추가하지 않습니다.
기존 DB를 먼저 export한 뒤 스키마를 감사하고, 별도 승인된 이관 또는 새
D1으로 교체합니다. V1 행은 V2 서명으로 재검증할 수 없으므로 임의로
`key_id`만 채우지 않습니다. 이관 후 첫 V2 스냅샷이 들어오기 전까지
`NO_DATA`를 유지하는 것이 정상입니다.

로컬/CI에서는 Python 표준 `sqlite3`로 동일 migration을 검증합니다.

```powershell
python -I scripts\validate_monitoring_migrations.py
```

## Pages binding과 encrypted keyring

Pages 프로젝트에는 다음 설정이 필요합니다.

- D1 binding: `MONITOR_DB`
- encrypted secret: `INGEST_HMAC_KEYS`
- variable: `COGNI_WORKSPACE_ID`
- variable: `MAX_SNAPSHOT_AGE_SECONDS=180`
- variable: `MAX_CLOCK_SKEW_SECONDS=300`
- build command: `npm run build`
- build output directory: `public`

`npm run build`는 Cloudflare Pages 빌드 환경의
`CF_PAGES_COMMIT_SHA`를 `functions/_lib/deployment.generated.js`에
결합합니다. Cloudflare가 제공하는 `CF_PAGES=1`, production branch
`CF_PAGES_BRANCH=main`, 40자리 `CF_PAGES_COMMIT_SHA`, 해당 프로젝트의 HTTPS
`CF_PAGES_URL`이 모두 일치하지 않으면 Pages 빌드는 실패합니다. 이 URL은
canonical alias가 아니라 해당 배포에만 속하는 고유
`*.cogni-os-orchestrator.pages.dev` URL이어야 합니다. preview
branch나 다른 Pages 프로젝트는 production 산출물로 승격되지 않습니다.
로컬이나 commit을 알 수 없는 환경에서 생성한 파일은
의도적으로 `build_bound=false`이며 릴리스 증거가 될 수 없습니다.

`CF_PAGES_PROJECT_NAME`은 Cloudflare Pages의 기본 주입 변수가 아니므로
사용하지 않습니다. 프로젝트 정체성은 고유 `CF_PAGES_URL`의 엄격한 host
검사로 결정합니다. GitHub Actions의 synthetic attribution 검사는 이 형식의
단위 테스트일 뿐 실제 배포 증거가 아닙니다. 실제 완료 판정은 Cloudflare
project API의 canonical deployment ID·direct URL·source commit과 production
health/snapshot을 별도로 수집해 일치시킨 경우에만 가능합니다.

키링 JSON은 interactive secret 입력으로 등록합니다. 아래 명령 실행 뒤
프롬프트에 JSON 한 줄을 붙여 넣고, 실제 값을 파일에 저장하지 않습니다.

```powershell
npx wrangler pages secret put INGEST_HMAC_KEYS `
  --project-name cogni-os-orchestrator
```

등록 후 Pages 배포가 새 binding과 secret을 읽는지 `/api/health`로
확인합니다. `wrangler.toml`에는 키 이름과 형식 안내만 남기며 실제
secret이나 가짜 D1 ID를 커밋하지 않습니다.

## publisher 실행

운영 publisher는 `python`, `git`, `powershell`을 `PATH`로 찾거나
`PYTHONPATH`, `PYTHONHOME`, `COGNI_PYTHON`으로 교체하지 않습니다. 직접
Python을 호출하는 예시는 개발 진단용일 뿐 운영 증거가 아닙니다. 운영
설치에는 다음 부트스트랩 경계가 먼저 필요합니다.

- 소스와 PowerShell bootstrap 파일 전체 경로가 SYSTEM, Administrators 또는
  TrustedInstaller 소유이고 일반 사용자·활성 비관리자 그룹이 쓸 수 없을 것
- 모든 경로 구성 요소가 non-reparse이고 실행 직전 SHA-256 재검사를 통과할 것
- Windows PowerShell, Git, Python은 코드에 고정된 관리자 소유 절대 경로일 것
- DPAPI용 `.runtime` 부모는 운영 사용자가 소유한 실제 디렉터리로 사전
  생성할 것. 스크립트가 임의 부모나 junction을 생성하지 않음

따라서 사용자 쓰기 가능한 checkout에서 운영 래퍼를 실행하면 secret을
읽기 전에 의도적으로 `NO_GO`입니다. 먼저 검증된 commit을 관리자 소유의
불변 배포 루트에 설치하고, 허용된 `C:\Program Files\Python312\python.exe`
또는 `C:\Program Files\Python310\python.exe`를 준비합니다. secret 회전은
Cloudflare keyring과 같은 값을 한 세션의 환경 변수로 전달해 DPAPI로
봉인한 뒤 즉시 환경 변수를 제거합니다.

운영 PC에서는 평문 환경 변수를 장기 저장하지 않고, 현재 Windows
사용자와 PC에 묶인 DPAPI `SecureString`을
`.runtime\cogni-monitor-secret.clixml`에 저장할 수 있습니다.
`.runtime/`은 Git에서 제외됩니다. 이 파일이 있으면 래퍼가 환경 변수보다
후순위로 읽으며, 기본 key ID는 `publisher-2026q3`입니다. 다른 key ID는
`COGNI_MONITOR_KEY_ID`로 명시합니다. DPAPI 파일은 다른 사용자나 다른
PC로 복사해 재사용하지 않습니다. sequence와 publisher lock도 기본적으로
`.runtime\monitor-publisher`에 저장하므로, 운영 원장이 읽기 전용으로
마운트되어 있어도 메타데이터를 게시할 수 있습니다. 이 디렉터리를
초기화하면 서버의 단조 증가 sequence 게이트가 낮은 값을 거절합니다.

GPU를 읽지 않는 제어 평면에서는 `--include-gpu` 또는 `-IncludeGpu`를
생략합니다. 이때 화면은 `GPU telemetry DISABLED`를 표시하며 수치를
꾸며내지 않습니다.

## 재부팅 자동복구와 단일 인스턴스

운영 PC에서는 로그온 시 publisher를 자동 복구하는 현재 사용자 범위의
예약 작업을 설치할 수 있습니다. 설치 명령은 HMAC secret을 예약 작업
인자나 환경 변수에 복사하지 않습니다. 기존의 현재 사용자·현재 PC 전용
DPAPI `SecureString` 파일 경로만 전달합니다.

```powershell
.\scripts\install_monitor_publisher_autostart.ps1 `
  -WorkspaceRoot "C:\comunity" `
  -IntervalSeconds 60 `
  -MaxBackoffSeconds 300
```

기본값은 GPU 텔레메트리 `DISABLED`입니다. 명시적으로 `-IncludeGpu`를
설치 옵션에 준 경우에도 collector는 GPU 0~5만 내보내고 6·7은 denylist
위반으로 표시하며 상세 수치를 외부로 보내지 않습니다.

자동복구 계약은 다음과 같습니다.

- Task Scheduler의 `AtLogOn`, `StartWhenAvailable`, crash 재시작 정책
- Task Scheduler `IgnoreNew`와 Python OS file lock의 이중 단일 인스턴스
- 프로세스 비정상 종료·재부팅 시 OS가 자동 해제하는 instance lock
- 연속 실패 시 게시 주기부터 최대 300초까지 지수 backoff
- `.runtime/monitor-publisher/monitor_publisher_journal.jsonl` 로컬 journal
- `.runtime/monitor-publisher/monitor_publisher_runtime.json` 원자적 상태 파일
- DPAPI 복호화 실패, 다른 사용자/PC 파일, reparse point, 비정상 크기를
  모두 네트워크 요청 전에 fail-closed 처리
- 시작할 때 orchestrator 저장소가 clean HEAD인지 확인하고 canonical
  `/api/health`가 HTTP 200, `CONFIGURED`, storage `READY`, `BUILD_BOUND`, 동일
  source commit, `minimum_release_snapshot_schema=1.2`,
  `operational_ingest_ready=true`인지 확인
- 위 production preflight가 하나라도 실패하면 Python publisher를 실행하지
  않고 로컬 wrapper journal에 bounded 오류만 기록

여기서 `BUILD_BOUND`와 `operational_ingest_ready=true`는 schema 1.2 signed
snapshot을 수집할 수 있다는 뜻일 뿐 릴리스 완료가 아닙니다. health의
`release_attribution_ready`는 API 증거를 HTTP 응답 자체가 자체 승인하지
못하도록 항상 `false`, `release_evidence_state=API_EVIDENCE_REQUIRED`로
유지합니다. 릴리스 승격은 별도 read-only Cloudflare project API에서 현재
production deployment ID, direct URL, commit을 수집해 content-addressed
archive와 signed ledger에 결합하고 재검증한 뒤에만 가능합니다.

따라서 과거 schema 1.0 publisher 예약 작업이 단순히 `Running`이거나 재시작
횟수가 많다는 사실은 준비 완료 증거가 아닙니다. D1 migration, 새 Pages 배포,
production health probe를 먼저 완료하고 같은 clean commit에서 예약 작업을
재설치·재시작합니다. 구 publisher를 새 서버 검증 전에 자동 재시작하지 않습니다.

publisher의 `PYTHONPATH`는 감시 대상 workspace의 `src`가 아니라 이
orchestrator 저장소의 `src`로 고정됩니다. 따라서 `C:\comunity`가 운영
증거 전용이거나 읽기 전용이어도 실행 코드의 출처가 바뀌지 않습니다.

예약 작업 제거:

```powershell
.\scripts\uninstall_monitor_publisher_autostart.ps1
```

DPAPI 파일을 다른 Windows 사용자·PC로 복사했거나 복호화가 실패하면
기존 파일을 억지로 재사용하지 않습니다. Cloudflare keyring을 새 값으로
회전한 동일 세션에서 새 secret을 현재 사용자 DPAPI로 다시 보호합니다.
평문은 명령 인자에 넣지 않습니다.

```powershell
$env:COGNI_MONITOR_INGEST_SECRET = "<Cloudflare에 등록한 새 secret>"
.\scripts\set_monitor_publisher_secret.ps1 -FromEnvironment
```

스크립트는 저장 후 환경 변수를 제거하고 파일 ACL을 현재 사용자 SID로
제한하며 즉시 복호화 검증합니다. keyring과 다른 임의 secret을 로컬에서
자동 생성하는 복구는 서버와 불일치하므로 제공하지 않습니다.

## 무중단 키 회전

키 제거는 단순 정리가 아니라 즉시 revocation입니다. 저장된 최신
스냅샷과 history도 현재 keyring으로 다시 검증하므로 반드시 overlap
기간을 둡니다.

1. 새 `key_id`와 32~256자 무작위 secret을 로컬에서 생성합니다.
2. `INGEST_HMAC_KEYS`에 기존 키와 새 키를 함께 넣습니다. 총 4개를
   넘지 않습니다.
3. Pages에 keyring을 등록하고 `/api/health`가 `CONFIGURED`인지
   확인합니다.
4. publisher의 `COGNI_MONITOR_KEY_ID`와
   `COGNI_MONITOR_INGEST_SECRET`을 새 키로 바꿉니다.
5. 기존보다 큰 sequence의 V2 스냅샷을 1개 이상 게시하고 HTTP 202뿐 아니라
   publisher가 출력한 sequence/body SHA-256이 전송 값과 정확히 일치하는지
   확인합니다. sequence를 초기화하거나 낮추지 않습니다.
6. `/api/snapshot`이 `LIVE`이고
   `monitoring.payload_signature_verified=true`,
   `monitoring.signature_verified=true`, `monitoring.fresh=true`,
   `monitoring.current_source_commit_bound=true`,
   `monitoring.deployment_verified=true`인지 함께 확인합니다.
7. D1의 최신 행이 새 키로 저장됐는지 확인합니다.

```powershell
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "SELECT sequence,key_id,observed_at,received_at FROM monitor_snapshots ORDER BY sequence DESC LIMIT 1;"
```

8. `monitor_history`는 workspace당 최근 720개를 보관하며 조회 시 각
   행을 현재 keyring으로 재검증합니다. 공개 `/api/history`에는 그중 현재
   BUILD_BOUND 배포·소스 커밋에 결속되고 TTL 안에 있는 행만 투영합니다.
   old-key 행이 모두 보존 기간에서 빠진 뒤에만 old key를 제거하는 것이
   가장 안전합니다.

```powershell
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "SELECT key_id,COUNT(*) AS rows FROM monitor_history GROUP BY key_id;"
```

old key의 행 수가 0이고 최신 snapshot이 new key임을 확인한 뒤 keyring에서
old key를 제거합니다. 15초 주기라면 720개 교체에는 약 3시간이 걸리지만,
일시 중단과 거절된 게시가 있을 수 있으므로 시간 추정 대신 D1 결과를
완료 기준으로 사용합니다.

## 롤백과 키 유출 대응

### 정상 회전 중 publisher 롤백

old/new 키가 모두 keyring에 있는 overlap 기간에는 publisher를 old
`key_id`/secret으로 되돌린 뒤 반드시 더 큰 sequence로 새 스냅샷을
게시합니다. 저장된 sequence나 state 파일을 과거 값으로 되돌리지
않습니다. 이후 최신 snapshot과 history에 필요한 키를 모두 유지합니다.

old key를 이미 제거했다면 먼저 old/new 키를 함께 keyring에 다시
등록하고 Pages 반영을 확인한 후 publisher를 롤백합니다. 최신 행을 old
키로 다시 게시하기 전에 keyring에서 new key를 제거하지 않습니다.

### secret 유출 또는 의심

유출된 키는 정상 overlap 절차보다 revocation을 우선합니다.

1. 안전한 새 키를 keyring에 추가합니다.
2. publisher를 새 키로 바꾸고 더 큰 sequence를 게시합니다.
3. 유출 키를 keyring에서 즉시 제거합니다.
4. 유출 키로 서명된 history가 `CORRUPT`가 되는 것은 의도된 fail-closed
   결과입니다. 화면을 정상처럼 보이게 하려고 유출 키를 재등록하지
   않습니다.
5. D1 export와 원장 증거를 별도 보존하고 사고 기록을 남깁니다.

활성 최신 행의 키를 먼저 제거하면 `/api/snapshot`은 새 키로 더 큰
sequence가 게시될 때까지 `CORRUPT`가 됩니다. D1 binding 또는 전체
keyring이 없거나 JSON이 잘못되면 `UNCONFIGURED`가 됩니다. 어떤 경우에도
검증되지 않은 데이터를 `LIVE`로 승격하지 않습니다.

## 운영 검증

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s src\cogni_os\tests -v
npm run check
npm test
node scripts\validate_p01_node.mjs
.\scripts\validate_p01_powershell.ps1
```

배포 후 확인:

1. `/api/health`가 `CONFIGURED`
2. publisher가 HTTP 202와 요청에 정확히 결합된 sequence/body SHA-256을 출력
3. `/api/snapshot`의 payload signature·freshness·current source commit·
   deployment 결속 4개 필드가 모두 `true`
4. `X-Cogni-Data-State: LIVE`
5. 180초 publisher 중단 후 `STALE`
6. 같은 nonce 재전송 시 HTTP 409
7. 같은/낮은 sequence 재전송 시 HTTP 409
8. GPU 6 또는 7 포함 시 HTTP 400
9. 누락·미등록·폐기 `key_id` 또는 잘못된 secret은 HTTP 401/503
10. D1 또는 전체 keyring 제거 시 화면이 `UNCONFIGURED`
11. 최신 행의 key를 제거하면 `CORRUPT`
12. old/new overlap 회전 뒤 새 key의 최신 행이 `LIVE`

운영 원장·태스크·보고서가 갱신되는 것은 정상이며 소스 변경과 분리해
표시합니다. `source.change_count`는 소스 변경만,
`source.operational_state.change_count`는 검증 대상 운영 증거 변경만
셉니다. `source.git_commit`과 `collector.attribution.source_commit`이
일치하지 않거나 운영 변경에 미분류 파일이 있으면 새 스냅샷은
릴리스 `PASS` 증거로 승격되지 않습니다. payload 서명만 유효하고 현재
배포·소스 결속이 없으면 `UNBOUND_DEPLOYMENT`로 닫히며 작업·GPU·진행률·
history 운영값을 노출하지 않습니다.
`reports/`와 `runs/`는 항상 변경 가능한 staging일 뿐 릴리스 진실이
아닙니다. `submissions/`와 `archive/` 아래 파일도 단순히 안전한 폴더에
있다는 이유로 신뢰하지 않습니다. signed ledger의 제출·검증·거절
사건에 동일 경로와 SHA-256이 결합되어야 하며, 실행 가능한 확장자,
미결합 파일, hash 불일치가 하나라도 있으면 operational state는
`valid=false`입니다.

Cloudflare 응답의 `deployment` 객체는 publisher 입력이 아니라 서버가
추가합니다. 정확한 production Pages 빌드가 생성한 불변 모듈과 signed
snapshot의 commit이 같을 때만 `BUILD_BOUND`입니다. 런타임 변수나 요청
payload가 주장하는 commit은 배포 귀속으로 사용하지 않으며 모두
`UNAVAILABLE`로 닫힙니다. 이 상태를 임의 커밋으로 채우거나 `PASS`로
승격하지 않습니다.

schema `1.0`과 `1.1`은 무중단 전환 중 읽기·표시 호환만 제공합니다. 신규
provenance 게이트가 없는 legacy snapshot은 `PASS`를 주장할 수 없습니다.
Phase 1의 배포 증거는 schema `1.2`, `LIVE`, payload signature·freshness·
current source commit·deployment 결속, clean source, ledger-bound operational
state, `BUILD_BOUND` commit을 모두 요구합니다.
또한 Cloudflare project API가 가리키는 현재 production deployment ID와
고유 deployment URL이 응답의 `release_deployment` 및 빌드 귀속과 정확히
일치해야 합니다. 같은 commit의 다른 deployment도 `NO_GO`입니다.

GPU `PASS`는 `nvidia-smi` telemetry만으로 만들지 않습니다. telemetry,
compute process, Docker DeviceRequests, Slurm/예약 증거 네 소스가 모두
`MEASURED`여야 합니다. 어느 하나가 disabled, unavailable, 생략이면 공개
상태는 `UNMEASURED`이고 릴리스는 `NO_GO`입니다. GPU 6·7은 0% 또는 19 MiB로
보이더라도 PID, container claim, scheduler reservation 중 하나라도 있으면
`POLICY_VIOLATION`입니다.

## 현재 공개 배포의 교정

2026-07-30 감사 시점의 기존 `/api/snapshot`은 작업, GPU, 원장 해시를
소스에 고정하고 요청 시각만 갱신했습니다. 따라서 기존 화면의
`실시간 연동`, `ACTIVE`, `VERIFIED`, GPU 수치는 실행 증거로 사용할 수
없습니다. 이 문서와 V2 함수가 배포되고 D1·keyring·publisher가 실제로
연결된 이후의 스냅샷부터 관제 증거로 인정합니다.

### 2026-08-07T06:21Z 공개 API 재감사

- `/api/health`: HTTP 200, `CONFIGURED`; D1 binding·storage·workspace·keyring은
  구성된 것으로 응답했다.
- `/api/snapshot`: HTTP 200이나 `X-Cogni-Data-State: STALE`, schema `1.0`,
  sequence `853`, 마지막 관측 `2026-08-01T03:15:23.934329Z`였다.
- snapshot의 서명은 검증됐지만 source commit은
  `3ac8a8b2f25c0d23ec5afcdb91e2062cc319b010`, `tree_clean=false`였고
  `deployment`는 `null`이었다.
- roadmap은 `trusted_complete=0/11`, progress는 `stale-unavailable`, release
  gate는 `NO_GO`였다.

따라서 저장소의 새 ACK 검증이 로컬·독립 시험을 통과한 것과 현재 공개 publisher가
실시간으로 동작한다는 주장은 분리한다. schema 1.2 publisher 재가동, exact ACK,
fresh snapshot, deployed commit/D1 독립 대조 전에는 공개 대시보드를 실시간 완료로
표시하지 않는다.
