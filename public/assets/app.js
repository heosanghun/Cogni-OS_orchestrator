// Cogni-OS Dashboard Frontend Logic
async function fetchSnapshot() {
  try {
    const res = await fetch('/api/snapshot', { cache: 'no-store' });
    if (!res.ok) throw new Error('API request failed');
    const data = await res.json();
    renderDashboard(data);
  } catch (err) {
    console.error('Failed to update dashboard:', err);
  }
}

function renderDashboard(data) {
  // Update progress bar
  const summary = data.tasks_summary || {};
  const percentage = summary.completion_percentage || 0;
  document.getElementById('progress-val').textContent = `${percentage.toFixed(1)}%`;
  document.getElementById('progress-fill').style.width = `${percentage}%`;

  // Update task metrics
  document.getElementById('count-pending').textContent = summary.pending || 0;
  document.getElementById('count-running').textContent = (summary.running || 0) + (summary.claimed || 0);
  document.getElementById('count-submitted').textContent = summary.submitted || 0;
  document.getElementById('count-verified').textContent = (summary.verified || 0) + (summary.archived || 0);

  // Render agents list
  const agentsList = data.agents || [];
  const agentContainer = document.getElementById('agent-cards');
  if (agentContainer) {
    agentContainer.innerHTML = agentsList.map(agent => `
      <div class="agent-card">
        <div class="agent-info">
          <div class="agent-avatar ${agent.id.includes('codex') ? 'avatar-codex' : 'avatar-antigravity'}">
            ${agent.id.slice(0, 2).toUpperCase()}
          </div>
          <div>
            <div class="agent-name">${agent.id}</div>
            <div class="agent-role">${agent.role} (${agent.model_family || 'custom'})</div>
          </div>
        </div>
        <span class="badge ${agent.status === 'RUNNING' ? 'badge-running' : agent.status === 'ACTIVE' ? 'badge-active' : 'badge-idle'}">
          ${agent.status}
        </span>
      </div>
    `).join('');
  }

  // Render ledger status
  const ledgerInfo = data.ledger || {};
  document.getElementById('ledger-status').textContent = `Ledger: ${ledgerInfo.status || 'VERIFIED'} · ${ledgerInfo.events_count || 0} Events`;
  document.getElementById('ledger-hash').textContent = `Head SHA-256: ${ledgerInfo.last_hash ? ledgerInfo.last_hash.slice(0, 16) + '...' : 'Genesis'}`;
}

// Initial fetch and auto-refresh loop
document.addEventListener('DOMContentLoaded', () => {
  fetchSnapshot();
  setInterval(fetchSnapshot, 3000);
});
