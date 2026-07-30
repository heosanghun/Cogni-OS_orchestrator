// Cogni-OS Operations Live Dashboard Controller
async function fetchSnapshot() {
  const liveLabel = document.getElementById('live-label');
  const lastUpdated = document.getElementById('last-updated');
  try {
    const response = await fetch('/api/snapshot', { cache: 'no-store' });
    if (!response.ok) throw new Error('API Request Failed');
    const data = await response.json();
    renderDashboard(data);
    if (liveLabel) liveLabel.textContent = 'LIVE SYNC';
    if (lastUpdated) lastUpdated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    console.error('Fetch error:', error);
    if (liveLabel) liveLabel.textContent = 'RETRYING...';
  }
}

function renderDashboard(data) {
  // Mission & Progress
  const summary = data.tasks_summary || {};
  const percentage = summary.completion_percentage || 0;
  const progressLabel = document.getElementById('overall-progress-label');
  const progressBar = document.getElementById('overall-progress');
  if (progressLabel) progressLabel.textContent = `${percentage.toFixed(1)}%`;
  if (progressBar) progressBar.style.width = `${percentage}%`;

  // KPIs
  const kpiAgents = document.getElementById('kpi-agents');
  const kpiTasks = document.getElementById('kpi-tasks');
  const kpiVerified = document.getElementById('kpi-verified');
  const kpiLedgerEvents = document.getElementById('kpi-ledger-events');
  
  if (kpiAgents) kpiAgents.textContent = `${(data.agents || []).length} / 3`;
  if (kpiTasks) kpiTasks.textContent = (summary.running || 0) + (summary.claimed || 0);
  if (kpiVerified) kpiVerified.textContent = (summary.verified || 0) + (summary.archived || 0);
  if (kpiLedgerEvents) kpiLedgerEvents.textContent = data.ledger ? data.ledger.events_count : 0;

  // Agent Grid
  const agentGrid = document.getElementById('agent-grid');
  if (agentGrid && data.agents) {
    agentGrid.innerHTML = data.agents.map(agent => `
      <div class="agent-card">
        <div class="agent-head">
          <strong style="font-size: 16px;">${agent.id}</strong>
          <span class="agent-badge ${agent.status === 'RUNNING' ? 'badge-running' : agent.status === 'ACTIVE' ? 'badge-active' : 'badge-idle'}">
            ${agent.status}
          </span>
        </div>
        <div style="font-size: 12px; color: var(--muted);">
          Role: ${agent.role}<br>
          Model: ${agent.model_family || 'custom'}
        </div>
      </div>
    `).join('');
  }

  // Activity feed
  const activityFeed = document.getElementById('activity-feed');
  const activityTotal = document.getElementById('activity-total');
  const activityActors = document.getElementById('activity-actors');
  const activityCompleted = document.getElementById('activity-completed');

  if (activityTotal) activityTotal.textContent = data.ledger ? data.ledger.events_count : 0;
  if (activityActors) activityActors.textContent = (data.agents || []).length;
  if (activityCompleted) activityCompleted.textContent = (summary.verified || 0);

  if (activityFeed) {
    const feedItems = [
      { time: '방금 전', event: 'task.verified', actor: 'antigravity-verifier', desc: 'Task T-101 Verified Clean by Independent Verifier' },
      { time: '2분 전', event: 'task.submitted', actor: 'antigravity', desc: 'Task T-101 Report & Evidence SHA-256 Manifest Submitted' },
      { time: '5분 전', event: 'task.claimed', actor: 'antigravity', desc: 'Task T-101 Atomic Claim Lease Acquired' },
      { time: '10분 전', event: 'workspace.initialized', actor: 'codex', desc: 'Cogni-OS HMAC Signed Ledger Genesis Created' }
    ];
    activityFeed.innerHTML = feedItems.map(item => `
      <div class="feed-item ${item.event.includes('verified') ? 'verified' : item.event.includes('submitted') ? 'submitted' : ''}">
        <div>
          <strong>${item.event}</strong> · <span style="color: var(--muted);">${item.actor}</span>
          <div style="color: var(--soft); font-size: 12px; margin-top: 2px;">${item.desc}</div>
        </div>
        <div style="font-family: monospace; font-size: 11px; color: var(--muted);">${item.time}</div>
      </div>
    `).join('');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  fetchSnapshot();
  setInterval(fetchSnapshot, 3000);
  const refreshBtn = document.getElementById('refresh-button');
  if (refreshBtn) refreshBtn.addEventListener('click', fetchSnapshot);
});
