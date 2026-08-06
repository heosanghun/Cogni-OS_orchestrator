// Cogni-OS Evidence Operations — no synthetic operational defaults.
const SVG_NS = "http://www.w3.org/2000/svg";
const STATE_LABELS = {
  LIVE: "서명 검증 LIVE",
  STALE: "STALE · 마지막 증거",
  NO_DATA: "서명 데이터 없음",
  UNCONFIGURED: "연동 미설정",
  CORRUPT: "데이터 손상",
  STORAGE_ERROR: "저장소 오류",
  FETCH_ERROR: "연결 오류",
};
const STATE_TITLES = {
  LIVE: "실제 운영 데이터가 서명·신선도 검증을 통과했습니다.",
  STALE: "마지막 증거는 유효하지만 최신 상태가 아닙니다.",
  NO_DATA: "서명 검증된 첫 운영 스냅샷을 기다립니다.",
  UNCONFIGURED: "Cloudflare 수신 저장소와 비밀키 연결이 필요합니다.",
  CORRUPT: "저장된 스냅샷이 구조 검증을 통과하지 못했습니다.",
  STORAGE_ERROR: "모니터링 저장소를 읽을 수 없습니다.",
  FETCH_ERROR: "공개 모니터링 API에 연결할 수 없습니다.",
};

const byId = (id) => document.getElementById(id);
const asArray = (value) => (Array.isArray(value) ? value : []);
const finite = (value) =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
const text = (id, value, fallback = "—") => {
  const node = byId(id);
  if (node) node.textContent = value === null || value === undefined ? fallback : String(value);
};
const formatPercent = (value) => {
  const parsed = finite(value);
  return parsed === null ? "—" : `${parsed.toFixed(parsed % 1 ? 1 : 0)}%`;
};
const formatGiB = (value) => {
  const parsed = finite(value);
  return parsed === null ? "—" : `${parsed.toFixed(1)} GiB`;
};
const formatTime = (value) => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed)
    ? new Intl.DateTimeFormat("ko-KR", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(new Date(parsed))
    : "—";
};
const shortHash = (value) =>
  typeof value === "string" && value.length >= 12 ? `${value.slice(0, 12)}…` : "—";
const urlHost = (value) => {
  try {
    return new URL(value).hostname || "—";
  } catch {
    return "—";
  }
};

let latestSnapshot = null;
let latestHistory = [];
let refreshInFlight = false;

function isLiveVerified(data) {
  return (
    data?.monitoring?.state === "LIVE" &&
    data?.monitoring?.signature_verified === true
  );
}

function evidenceSafeView(raw) {
  const data = raw && typeof raw === "object" ? raw : {};
  if (isLiveVerified(data)) return data;

  const reportedState = String(data.monitoring?.state || "UNCONFIGURED");
  const state = reportedState === "LIVE" ? "CORRUPT" : reportedState;
  const reason =
    reportedState === "LIVE"
      ? "LIVE 응답의 서명 검증 플래그가 유효하지 않아 운영 값을 숨겼습니다."
      : data.monitoring?.reason || "최신 서명 운영 증거를 사용할 수 없습니다.";
  const observedAt =
    typeof data.monitoring?.observed_at === "string"
      ? data.monitoring.observed_at
      : null;
  const alerts = asArray(data.alerts);

  return {
    ...data,
    monitoring: {
      ...data.monitoring,
      state,
      reason,
      signature_verified:
        state === "STALE" && data.monitoring?.signature_verified === true,
    },
    tasks_summary: {
      total: 0,
      pending: 0,
      claimed: 0,
      running: 0,
      blocked: 0,
      submitted: 0,
      trusted_verified: 0,
      verification_disputed: 0,
      verification_revoked: 0,
      rejected: 0,
      current_release_validated: 0,
      completion_percentage: null,
      progress_basis: "unavailable",
    },
    roadmap: {
      schema_version: 1,
      total: 11,
      trusted_complete: 0,
      current_release_validated: 0,
      progress_percent: null,
      progress_basis: "unavailable",
      phases: [],
    },
    agents: [],
    tasks: [],
    ledger_events: [],
    ledger: {
      status: state === "STALE" ? "STALE" : "NOT_VERIFIED",
      valid: false,
      signed: false,
      events: 0,
      head: null,
    },
    gpus: [],
    gpu_policy: {
      allowed_ids: [0, 1, 2, 3, 4, 5],
      denied_ids: [6, 7],
      telemetry_state: "UNMEASURED",
      violating_ids: [],
      measurement_complete: false,
      source_states: {
        telemetry: "UNAVAILABLE",
        processes: "UNAVAILABLE",
        containers: "UNAVAILABLE",
        scheduler: "UNAVAILABLE",
      },
      evidence_counts: {
        processes: 0,
        container_claims: 0,
        scheduler_reservations: 0,
      },
    },
    resources: {},
    release_gate: {
      status: "NO_GO",
      reasons: [reason],
      evidence_sha256: null,
    },
    release_deployment: null,
    source: { git_commit: "unknown" },
    alerts:
      alerts.length > 0
        ? alerts
        : [
            {
              severity: "critical",
              code: state,
              message: reason,
              observed_at: observedAt || new Date().toISOString(),
            },
          ],
  };
}

function create(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) node.textContent = String(value);
  return node;
}

function setEmpty(emptyId, containerId, isEmpty) {
  const empty = byId(emptyId);
  const container = byId(containerId);
  if (empty) empty.hidden = !isEmpty;
  if (container) container.hidden = isEmpty;
}

function stateClass(value) {
  const normalized = String(value || "").toLowerCase().replaceAll("_", "-");
  return `state-${normalized}`;
}

function badgeClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "verified" || normalized === "ready" || normalized === "pass") {
    return "badge-active";
  }
  if (normalized === "running" || normalized === "configured") return "badge-running";
  if (
    normalized.includes("disputed") ||
    normalized === "blocked" ||
    normalized === "rejected" ||
    normalized === "invalidated"
  ) {
    return "badge-blocked";
  }
  return "badge-idle";
}

function renderTrust(data) {
  const monitoring = data.monitoring || {};
  const state = monitoring.state || "UNCONFIGURED";
  const banner = byId("trust-banner");
  if (banner) {
    banner.className = `trust-banner ${stateClass(state)}`;
  }
  text("live-label", STATE_LABELS[state] || state);
  text("trust-title", STATE_TITLES[state] || "모니터링 상태를 확인할 수 없습니다.");
  text("trust-reason", monitoring.reason);
  text("trust-sequence", monitoring.sequence);
  text(
    "trust-age",
    finite(monitoring.age_seconds) === null
      ? null
      : `${monitoring.age_seconds.toFixed(1)}초`,
  );
  text("trust-hash", shortHash(monitoring.body_sha256));
  text("last-updated", formatTime(monitoring.observed_at));
  text("workspace-name", data.workspace_name);

  const dot = byId("live-dot");
  if (dot) dot.className = state === "LIVE" ? "status-dot live" : "status-dot";
}

function renderMission(data) {
  const roadmap = data.roadmap || {};
  const percentage = finite(roadmap.progress_percent);
  text("overall-progress-label", formatPercent(percentage));
  const bar = byId("overall-progress");
  const track = byId("overall-progress-track");
  const width = percentage === null ? 0 : Math.min(100, Math.max(0, percentage));
  if (bar) bar.style.width = `${width}%`;
  if (track) track.setAttribute("aria-valuenow", String(width));

  const gate = isLiveVerified(data)
    ? data.release_gate || { status: "NO_GO", reasons: ["증거 없음"] }
    : {
        status: "NO_GO",
        reasons: [
          data.monitoring?.reason || "최신 서명 운영 증거를 사용할 수 없습니다.",
        ],
      };
  text("release-gate-status", gate.status || "NO_GO");
  const gateNode = byId("release-gate");
  if (gateNode) {
    gateNode.className = `release-gate ${stateClass(gate.status || "NO_GO")}`;
  }
  const reasons = asArray(gate.reasons);
  const nextPhase = asArray(roadmap.phases).find(
    (phase) => phase.trusted_complete !== true,
  );
  text(
    "next-milestone",
    gate.status === "PASS"
      ? "독립 검증된 릴리스 증거 보관"
      : nextPhase
        ? `${nextPhase.id} · ${nextPhase.title} — ${nextPhase.state}`
        : reasons[0] || "릴리스 증거가 부족합니다.",
  );
}

function renderKpis(data) {
  const live = isLiveVerified(data);
  const agents = asArray(data.agents);
  const attested = agents.filter((agent) =>
    ["READY", "BUSY"].includes(agent.status),
  ).length;
  text("kpi-agents", live ? `${attested} / ${agents.length}` : null);
  text(
    "kpi-agents-note",
    live
      ? agents.length
        ? "최근 attestation 기준"
        : "등록 정보 없음"
      : "LIVE 증거 대기",
  );

  const summary = data.tasks_summary || {};
  const roadmap = data.roadmap || {};
  text("kpi-tasks", live ? summary.running ?? 0 : null);
  text(
    "kpi-tasks-note",
    live
      ? `대기 ${summary.pending ?? 0} · 제출 ${summary.submitted ?? 0}`
      : "LIVE 증거 대기",
  );
  text("kpi-verified", live ? roadmap.trusted_complete ?? 0 : null);
  text(
    "kpi-verified-note",
    live
      ? `Historical ${roadmap.trusted_complete ?? 0} / ${roadmap.total ?? 11} · Current release ${roadmap.current_release_validated ?? 0}`
      : "LIVE 증거 대기",
  );

  const gpus = asArray(data.gpus);
  const gpuAverage = gpus.length
    ? gpus.reduce((sum, gpu) => sum + (finite(gpu.utilization) || 0), 0) / gpus.length
    : null;
  const gpuMeasured = data.gpu_policy?.measurement_complete === true;
  text("kpi-gpu", live && gpuMeasured ? formatPercent(gpuAverage) : null);
  text(
    "kpi-gpu-note",
    live && gpuMeasured && gpus.length
      ? `${gpus.filter((gpu) => gpu.utilization > 0).length} / ${gpus.length} 활성`
      : `GPU 증거 ${data.gpu_policy?.telemetry_state || "UNMEASURED"} · release NO_GO`,
  );

  const disk = data.resources?.disk || {};
  text("kpi-disk", live ? formatPercent(finite(disk.percent)) : null);
  text(
    "kpi-disk-note",
    live
      ? `${formatGiB(disk.used_gib)} / ${formatGiB(disk.total_gib)}`
      : "LIVE 증거 대기",
  );
  const alerts = asArray(data.alerts);
  text("kpi-alerts", alerts.length);
  text("kpi-alerts-note", alerts.length ? "검토 필요" : "수신 경고 없음");
}

function renderAgents(data) {
  const agents = asArray(data.agents);
  const grid = byId("agent-grid");
  setEmpty("agents-empty", "agent-grid", agents.length === 0);
  if (!grid) return;
  const cards = agents.map((agent) => {
    const card = create("article", "agent-card");
    const head = create("div", "agent-head");
    head.append(
      create("strong", "agent-name", agent.id),
      create("span", `agent-badge ${badgeClass(agent.status)}`, agent.status),
    );
    const details = create("dl", "agent-details");
    [
      ["역할", agent.role],
      ["모드", agent.mode],
      ["현재 수행", agent.current_task || "할당 없음"],
      ["측정 진행률", formatPercent(finite(agent.task_progress))],
      ["다음 단계", agent.next_step || "상태 확인"],
    ].forEach(([label, value]) => {
      const row = create("div");
      row.append(create("dt", null, label), create("dd", null, value));
      details.append(row);
    });
    card.append(head, details);
    return card;
  });
  grid.replaceChildren(...cards);
  text("agents-meta", `${agents.filter((agent) => agent.status === "READY").length} attested`);
}

function renderLedger(data) {
  const ledger = data.ledger || {};
  const events = asArray(data.ledger_events).slice().reverse();
  const feed = byId("activity-feed");
  renderActivityHistogram(events);
  setEmpty("activity-empty", "activity-feed", events.length === 0);
  text(
    "ledger-status",
    ledger.valid ? `VERIFIED · ${ledger.events} events` : "NOT VERIFIED",
  );
  text("activity-total", ledger.events ?? 0);
  text("activity-head", shortHash(ledger.head));
  text(
    "activity-submitted",
    events.filter((event) => event.action === "task.submitted").length,
  );
  text(
    "activity-disputed",
    (data.tasks_summary?.verification_disputed ?? 0) +
      (data.tasks_summary?.verification_revoked ?? 0),
  );
  if (!feed) return;
  const items = events.slice(0, 60).map((event) => {
    const item = create(
      "article",
      `feed-item ${
        event.action?.includes("verified")
          ? "verified"
          : event.action?.includes("submitted")
            ? "submitted"
            : event.action?.includes("blocked") || event.action?.includes("rejected")
              ? "blocked"
              : ""
      }`,
    );
    const copy = create("div");
    copy.append(
      create("strong", null, event.actor || "unknown"),
      create("span", "feed-action", event.action || "unknown"),
      create(
        "div",
        "feed-task",
        event.task_title || event.task_id || "workspace",
      ),
    );
    item.append(copy, create("time", null, formatTime(event.timestamp)));
    return item;
  });
  feed.replaceChildren(...items);
}

function eventCategory(action) {
  const normalized = String(action || "").toLowerCase();
  if (normalized.includes("verified") || normalized.includes("archived")) {
    return "success";
  }
  if (normalized.includes("submitted")) return "evidence";
  if (
    normalized.includes("blocked") ||
    normalized.includes("rejected") ||
    normalized.includes("invalidated") ||
    normalized.includes("failed")
  ) {
    return "issue";
  }
  return "work";
}

function renderActivityHistogram(events) {
  const histogram = byId("activity-histogram");
  if (!histogram) return;
  const currentHour = new Date();
  currentHour.setMinutes(0, 0, 0);
  const buckets = Array.from({ length: 24 }, (_, index) => {
    const start = currentHour.getTime() - (23 - index) * 60 * 60 * 1000;
    return {
      start,
      end: start + 60 * 60 * 1000,
      work: 0,
      evidence: 0,
      success: 0,
      issue: 0,
    };
  });
  for (const event of events) {
    const timestamp = Date.parse(event.timestamp);
    if (!Number.isFinite(timestamp)) continue;
    const bucket = buckets.find(
      (candidate) => timestamp >= candidate.start && timestamp < candidate.end,
    );
    if (bucket) bucket[eventCategory(event.action)] += 1;
  }
  const totals = buckets.map(
    (bucket) =>
      bucket.work + bucket.evidence + bucket.success + bucket.issue,
  );
  const maxTotal = Math.max(1, ...totals);
  const columns = buckets.map((bucket, index) => {
    const total = totals[index];
    const column = create("div", "histogram-column");
    const count = create("span", "histogram-count", total || "");
    const track = create("div", "histogram-track");
    track.style.height = `${Math.max(4, (total / maxTotal) * 100)}%`;
    for (const category of ["issue", "success", "evidence", "work"]) {
      if (!bucket[category] || total === 0) continue;
      const segment = create("span", `histogram-segment histogram-${category}`);
      segment.style.height = `${(bucket[category] / total) * 100}%`;
      track.append(segment);
    }
    const hour = new Date(bucket.start).getHours();
    const label = create(
      "span",
      "histogram-hour",
      index % 3 === 0 || index === 23 ? `${String(hour).padStart(2, "0")}시` : "",
    );
    column.title = `${String(hour).padStart(2, "0")}시 · ${total}건`;
    column.append(count, track, label);
    return column;
  });
  histogram.replaceChildren(...columns);
}

function renderGpus(data) {
  const gpus = asArray(data.gpus).filter((gpu) => gpu.id >= 0 && gpu.id <= 5);
  const list = byId("gpu-list");
  setEmpty("gpu-empty", "gpu-list", gpus.length === 0);
  text(
    "gpu-policy",
    `GPU 0~5 ${data.gpu_policy?.measurement_complete === true ? "FULLY MEASURED" : "UNMEASURED · NO_GO"} · GPU 6·7 DENIED`,
  );
  if (!list) return;
  const cards = gpus.map((gpu) => {
    const card = create("article", "gpu-card");
    const head = create("div", "gpu-head");
    head.append(
      create("strong", null, `GPU ${gpu.id}`),
      create("span", "gpu-utilization", formatPercent(gpu.utilization)),
    );
    card.append(
      head,
      create("div", "gpu-name", gpu.name),
      create(
        "div",
        "gpu-details",
        `VRAM ${formatGiB(gpu.vram_used_gib)} / ${formatGiB(gpu.vram_total_gib)}`,
      ),
      create(
        "div",
        "gpu-details",
        `${finite(gpu.temperature_c) ?? "—"}°C · ${finite(gpu.power_w) ?? "—"}W`,
      ),
    );
    return card;
  });
  list.replaceChildren(...cards);
}

function renderTasks(data) {
  const tasks = asArray(data.tasks);
  const body = byId("task-tbody");
  setEmpty("tasks-empty", "task-table", tasks.length === 0);
  text("task-count", `${tasks.length}개 작업`);
  if (!body) return;
  const rows = tasks.map((task) => {
    const row = document.createElement("tr");
    const taskCell = document.createElement("td");
    taskCell.append(
      create("strong", null, task.title),
      create("small", "task-id", ` ${task.id}`),
    );
    const stateCell = document.createElement("td");
    stateCell.append(
      create(
        "span",
        `agent-badge ${badgeClass(task.current_release_state)}`,
        `current: ${task.current_release_state}`,
      ),
      create(
        "small",
        "task-id",
        ` historical: ${task.historical_state}`,
      ),
    );
    [
      taskCell,
      create("td", null, task.owner),
      stateCell,
      create("td", "mono", formatPercent(finite(task.progress))),
      create("td", null, task.next_step),
      create("td", "muted", formatTime(task.updated_at)),
    ].forEach((cell) => row.append(cell));
    return row;
  });
  body.replaceChildren(...rows);
}

function renderResources(data) {
  const resources = data.resources || {};
  const memory = resources.memory || {};
  const disk = resources.disk || {};
  text("memory-title", `${formatGiB(memory.used_gib)} / ${formatGiB(memory.total_gib)}`);
  text("memory-percent", formatPercent(finite(memory.percent)));
  text("disk-title", `${formatGiB(disk.used_gib)} / ${formatGiB(disk.total_gib)}`);
  text("disk-percent", formatPercent(finite(disk.percent)));
  text("system-load", finite(resources.load_average_1m));
  const uptime = finite(resources.uptime_seconds);
  text("system-uptime", uptime === null ? null : `${Math.floor(uptime / 86400)}일`);
  text("source-commit", shortHash(data.source?.git_commit));
  text(
    "collector-commit",
    shortHash(data.collector?.attribution?.source_commit),
  );
  text("deployment-attribution", data.deployment?.attribution);
  text("deployment-commit", shortHash(data.deployment?.source_commit));
  text("deployment-id", data.release_deployment?.deployment_id);
  text(
    "deployment-direct-url",
    urlHost(data.release_deployment?.deployment_url || data.deployment?.deployment_url),
  );
  const operationalChanges = finite(
    data.source?.operational_state?.change_count,
  );
  text(
    "operational-change-count",
    operationalChanges === null ? null : `${operationalChanges} files`,
  );
  text(
    "evidence-reference-count",
    finite(data.source?.operational_state?.reference_count),
  );
  text(
    "evidence-conflict-count",
    finite(data.source?.operational_state?.conflict_count),
  );
  text(
    "evidence-missing-count",
    finite(data.source?.operational_state?.missing_count),
  );
}

function renderAlerts(data) {
  const alerts = asArray(data.alerts);
  const list = byId("alerts-list");
  setEmpty("alerts-empty", "alerts-list", alerts.length === 0);
  if (!list) return;
  const items = alerts.map((alert) => {
    const item = create(
      "article",
      `alert-item alert-${alert.severity || "warning"}`,
    );
    item.append(
      create("strong", null, alert.code || "OPERATIONAL_ALERT"),
      create("span", null, alert.message || "상세 내용 없음"),
      create("time", null, formatTime(alert.observed_at)),
    );
    return item;
  });
  list.replaceChildren(...items);
}

function renderLineChart(svgId, values, color, { min = 0, max = 100 } = {}) {
  const svg = byId(svgId);
  if (!svg) return;
  svg.replaceChildren();
  if (!values.length) return;
  const width = Math.max(300, svg.clientWidth || 300);
  const height = Math.max(140, svg.clientHeight || 140);
  const usable = Math.max(1, max - min);
  const points = values
    .map((raw, index) => {
      const value = Math.max(min, Math.min(max, raw));
      const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width;
      const y = height - ((value - min) / usable) * (height - 24) - 12;
      return `${x},${y}`;
    })
    .join(" ");
  const polyline = document.createElementNS(SVG_NS, "polyline");
  polyline.setAttribute("points", points);
  polyline.setAttribute("fill", "none");
  polyline.setAttribute("stroke", color);
  polyline.setAttribute("stroke-width", "3");
  polyline.setAttribute("stroke-linecap", "round");
  polyline.setAttribute("stroke-linejoin", "round");
  svg.append(polyline);
}

function renderHistory() {
  const utilization = latestHistory
    .map((entry) => {
      const gpus = asArray(entry.gpus).filter((gpu) => gpu.id >= 0 && gpu.id <= 5);
      return gpus.length
        ? gpus.reduce((sum, gpu) => sum + (finite(gpu.utilization) || 0), 0) /
            gpus.length
        : null;
    })
    .filter((value) => value !== null);
  const temperature = latestHistory
    .map((entry) => {
      const values = asArray(entry.gpus)
        .filter((gpu) => gpu.id >= 0 && gpu.id <= 5)
        .map((gpu) => finite(gpu.temperature_c))
        .filter((value) => value !== null);
      return values.length ? Math.max(...values) : null;
    })
    .filter((value) => value !== null);
  renderLineChart("utilization-chart", utilization, "#38bdf8");
  renderLineChart("temperature-chart", temperature, "#f59e0b", {
    min: 0,
    max: 100,
  });
  text("util-range", utilization.length ? `${utilization.length}개 서명 스냅샷` : null);
  text(
    "temperature-peak",
    temperature.length ? `최고 ${Math.max(...temperature).toFixed(0)}°C` : null,
  );
}

function renderDashboard(data) {
  const safeData = evidenceSafeView(data);
  latestSnapshot = safeData;
  renderTrust(safeData);
  renderMission(safeData);
  renderKpis(safeData);
  renderAgents(safeData);
  renderLedger(safeData);
  renderGpus(safeData);
  renderTasks(safeData);
  renderResources(safeData);
  renderAlerts(safeData);
}

function fetchWithTimeout(url, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { cache: "no-store", signal: controller.signal }).finally(() =>
    clearTimeout(timeout),
  );
}

async function refreshSnapshot() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const response = await fetchWithTimeout("/api/snapshot");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderDashboard(await response.json());
  } catch (error) {
    renderDashboard({
      workspace_name: "연결 실패",
      monitoring: {
        state: "FETCH_ERROR",
        reason: "모니터링 API 응답을 받지 못했습니다.",
        signature_verified: false,
      },
      tasks_summary: {},
      agents: [],
      tasks: [],
      ledger_events: [],
      ledger: { valid: false, events: 0 },
      gpus: [],
      gpu_policy: { telemetry_state: "UNMEASURED", measurement_complete: false },
      resources: {},
      alerts: [
        {
          severity: "critical",
          code: "FETCH_ERROR",
          message: String(error.message || error),
          observed_at: new Date().toISOString(),
        },
      ],
      release_gate: { status: "NO_GO", reasons: ["모니터링 연결 실패"] },
      release_deployment: null,
      source: { git_commit: "unknown" },
    });
  } finally {
    refreshInFlight = false;
  }
}

async function refreshHistory() {
  try {
    const response = await fetchWithTimeout("/api/history?limit=120");
    if (!response.ok) return;
    const data = await response.json();
    latestHistory = data.ok ? asArray(data.history) : [];
    renderHistory();
  } catch {
    latestHistory = [];
    renderHistory();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const refreshButton = byId("refresh-button");
  if (refreshButton) {
    refreshButton.addEventListener("click", () => {
      refreshSnapshot();
      refreshHistory();
    });
  }
  refreshSnapshot();
  refreshHistory();
  window.setInterval(refreshSnapshot, 5000);
  window.setInterval(refreshHistory, 30000);
});
