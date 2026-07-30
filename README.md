# Cogni-OS Orchestrator 🚀

**Cogni-OS**는 **Codex (지휘자 / Conductor)**와 **Antigravity (멀티에이전트 수행자 & 독립 검증자)** 간의 증거 기반 불변 원장(Evidence-First Ledger)을 바탕으로 동장하는 차세대 멀티에이전트 오케스트레이션 운영체제(OS)입니다.

---

## 🌟 Key Features

- **Codex Conductor & Antigravity Fleet Topology**:
  - Claude를 완전히 배제하고, **Codex**가 오케스트레이터로서 작업을 분할 및 관리하며 **Antigravity**가 수행자(Executant) 및 독립 검증자(Verifier)로 동작합니다.
- **Evidence-First Verification State Machine**:
  - `Pending` ➔ `Claimed` ➔ `Running` ➔ `Submitted` ➔ `Verified` ➔ `Archived`
  - 에이전트의 종료 코드나 텍스트 보고서에 의존하지 않고, SHA-256 증거 매니페스트 및 알려진 값(Known-answer) 검증을 거친 항목만 최종 승인합니다.
- **Append-only HMAC Signed Evidence Ledger**:
  - 모든 상태 변경 및 트랜잭션은 `events.jsonl`에 암호화 해시 체인 및 HMAC 서명으로 기록되어 조작이 불가능합니다.
- **Real-Time Live Web Dashboard & Cloudflare Pages Integration**:
  - 사용자 작업 진행률 (Progress %), 에이전트 토폴로지 Card, 태스크 파이프라인, 원장 타임라인을 한눈에 볼 수 있는 웹 대시보드가 탑재되어 있습니다.
  - `wrangler.toml` 및 `public/`, `functions/api/snapshot.js` 지원으로 Cloudflare Pages / Workers에 바로 배포 가능합니다.

---

## 🚀 Quick Start

### 1. Installation

Python 3.10 이상 환경에서 패키지를 설치합니다:

```bash
pip install -e .
```

### 2. Workspace Initialization

Cogni-OS 워크스페이스를 초기화합니다:

```bash
cogni init ./cogni-workspace \
  --name "Cogni-OS Production Workspace" \
  --orchestrator codex \
  --control-principal codex-conductor \
  --model-family openai-codex \
  --preset cogni-codex-antigravity
```

### 3. Creating & Executing Tasks

Codex Conductor가 태스크를 추가하고, Antigravity 수행자가 작업을 수행합니다:

```bash
# 1. Codex Conductor adds a task
cogni task add ./cogni-workspace \
  --actor codex \
  --id T-101 \
  --owner antigravity \
  --title "Implement Core Data Validation Engine" \
  --description "Build robust validation pipeline"

# 2. Antigravity claims and starts the task
cogni task claim ./cogni-workspace --actor antigravity --id T-101
cogni task start ./cogni-workspace --actor antigravity --id T-101 --lease-token "<TOKEN>"

# 3. Antigravity submits report & evidence manifest
cogni task submit ./cogni-workspace \
  --actor antigravity \
  --id T-101 \
  --lease-token "<TOKEN>" \
  --report ./cogni-workspace/reports/antigravity/T-101.md \
  --evidence ./cogni-workspace/reports/antigravity/T-101.evidence.json

# 4. Antigravity Verifier independently verifies
cogni task verify ./cogni-workspace \
  --actor antigravity-verifier \
  --id T-101 \
  --decision accept \
  --note "Independent known-answer tests reproduced clean."
```

### 4. Running Operational Dashboard

```bash
cogni dashboard ./cogni-workspace --port 8484
```

웹 브라우저에서 `http://127.0.0.1:8484`에 접속하여 실시간 모니터링을 확인하세요.

---

## ☁️ Deploying to Cloudflare Pages

프로젝트 루트 디렉토리에서 Cloudflare Pages로 배포할 수 있습니다:

```bash
npx wrangler pages deploy public --project-name cogni-os-orchestrator
```

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.
