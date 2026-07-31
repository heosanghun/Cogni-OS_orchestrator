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

## 데이터 경계

publisher는 다음 운영 메타데이터만 외부 관제 채널에 전송합니다.

- task ID, 제목, 담당, 상태, 시각
- P01~P11의 신뢰 상태와 `trusted_complete / 11` 기반 진행률
- 검증 신뢰 상태와 원장 head hash
- 실행 주체의 공개 상태 및 attestation 여부
- GPU 0~5의 사용률·VRAM·온도·전력
- 시스템 메모리·디스크·load·uptime
- release gate 상태와 증거 SHA-256

프롬프트, 고객 데이터, 모델 입출력, 소스 내용, 환경 변수, 비밀키,
파일 내용, 제어 명령은 전송하지 않습니다. 공개 API는 Cogni-Core로
명령을 전달하는 경로를 제공하지 않습니다.

## Cloudflare D1 준비

실제 Cloudflare 계정에서 데이터베이스를 생성하고 반환된 실제 ID만
`wrangler.toml`의 주석 처리된 `d1_databases` 블록에 입력합니다.
binding 이름은 반드시 `MONITOR_DB`여야 합니다.

```powershell
npx wrangler d1 create cogni-os-monitoring
npx wrangler d1 execute cogni-os-monitoring `
  --remote `
  --file migrations/0001_monitoring.sql
```

스키마 적용 뒤 `key_id` 열과 필수 index를 확인합니다.

```powershell
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA table_info(monitor_snapshots);"
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA table_info(monitor_history);"
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA table_info(monitor_nonces);"
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "PRAGMA index_list(monitor_history);"
```

`0001_monitoring.sql`은 신규 데이터베이스 기준입니다. 이미 V1 테이블이
존재한다면 `CREATE TABLE IF NOT EXISTS`는 `key_id` 열을 추가하지 않습니다.
기존 DB를 먼저 export한 뒤 스키마를 감사하고, 별도 승인된 이관 또는 새
D1으로 교체합니다. V1 행은 V2 서명으로 재검증할 수 없으므로 임의로
`key_id`만 채우지 않습니다. 이관 후 첫 V2 스냅샷이 들어오기 전까지
`NO_DATA`를 유지하는 것이 정상입니다.

로컬/CI에서는 Python 표준 `sqlite3`로 동일 migration을 검증합니다.

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s src\cogni_os\tests -p "test_monitoring_migration.py" -v
```

## Pages binding과 encrypted keyring

Pages 프로젝트에는 다음 설정이 필요합니다.

- D1 binding: `MONITOR_DB`
- encrypted secret: `INGEST_HMAC_KEYS`
- variable: `COGNI_WORKSPACE_ID`
- variable: `MAX_SNAPSHOT_AGE_SECONDS=180`
- variable: `MAX_CLOCK_SKEW_SECONDS=300`

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

Cloudflare keyring의 한 항목과 동일한 `key_id`/secret을 운영 호스트의
환경 변수에 설정합니다. 두 변수 중 하나라도 없거나 형식이 틀리면
PowerShell 래퍼는 네트워크 요청 전에 중단합니다.

```powershell
$env:COGNI_MONITOR_KEY_ID = "publisher-2026q3"
$env:COGNI_MONITOR_INGEST_SECRET = "<matching-32-256-char-secret>"
$env:PYTHONPATH = "$PWD\src"
python -B scripts\publish_monitor_snapshot.py . `
  --key-id $env:COGNI_MONITOR_KEY_ID `
  --include-gpu `
  --interval-seconds 15
```

PowerShell 래퍼:

```powershell
$env:COGNI_MONITOR_KEY_ID = "publisher-2026q3"
$env:COGNI_MONITOR_INGEST_SECRET = "<matching-32-256-char-secret>"
$env:COGNI_PYTHON = "C:\Path\To\python.exe"
.\scripts\run_monitor_publisher.ps1 -WorkspaceRoot $PWD -IncludeGpu
```

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

- Task Scheduler의 `AtLogOn`, `StartWhenAvailable`, 1분 재시작 정책
- Task Scheduler `IgnoreNew`와 Python OS file lock의 이중 단일 인스턴스
- 프로세스 비정상 종료·재부팅 시 OS가 자동 해제하는 instance lock
- 연속 실패 시 게시 주기부터 최대 300초까지 지수 backoff
- `.runtime/monitor-publisher/monitor_publisher_journal.jsonl` 로컬 journal
- `.runtime/monitor-publisher/monitor_publisher_runtime.json` 원자적 상태 파일
- DPAPI 복호화 실패, 다른 사용자/PC 파일, reparse point, 비정상 크기를
  모두 네트워크 요청 전에 fail-closed 처리

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
5. 기존보다 큰 sequence의 V2 스냅샷을 1개 이상 게시하고 HTTP 202를
   확인합니다. sequence를 초기화하거나 낮추지 않습니다.
6. `/api/snapshot`이 `LIVE`,
   `monitoring.signature_verified=true`인지 확인합니다.
7. D1의 최신 행이 새 키로 저장됐는지 확인합니다.

```powershell
npx wrangler d1 execute cogni-os-monitoring --remote `
  --command "SELECT sequence,key_id,observed_at,received_at FROM monitor_snapshots ORDER BY sequence DESC LIMIT 1;"
```

8. `monitor_history`는 workspace당 최근 720개를 보관하며 조회 시 각
   행을 현재 keyring으로 재검증합니다. old-key 행이 모두 보존 기간에서
   빠진 뒤에만 old key를 제거하는 것이 가장 안전합니다.

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
```

배포 후 확인:

1. `/api/health`가 `CONFIGURED`
2. publisher가 HTTP 202와 sequence/body SHA-256을 출력
3. `/api/snapshot`의 `monitoring.signature_verified=true`
4. `X-Cogni-Data-State: LIVE`
5. 180초 publisher 중단 후 `STALE`
6. 같은 nonce 재전송 시 HTTP 409
7. 같은/낮은 sequence 재전송 시 HTTP 409
8. GPU 6 또는 7 포함 시 HTTP 400
9. 누락·미등록·폐기 `key_id` 또는 잘못된 secret은 HTTP 401/503
10. D1 또는 전체 keyring 제거 시 화면이 `UNCONFIGURED`
11. 최신 행의 key를 제거하면 `CORRUPT`
12. old/new overlap 회전 뒤 새 key의 최신 행이 `LIVE`

## 현재 공개 배포의 교정

2026-07-30 감사 시점의 기존 `/api/snapshot`은 작업, GPU, 원장 해시를
소스에 고정하고 요청 시각만 갱신했습니다. 따라서 기존 화면의
`실시간 연동`, `ACTIVE`, `VERIFIED`, GPU 수치는 실행 증거로 사용할 수
없습니다. 이 문서와 V2 함수가 배포되고 D1·keyring·publisher가 실제로
연결된 이후의 스냅샷부터 관제 증거로 인정합니다.
