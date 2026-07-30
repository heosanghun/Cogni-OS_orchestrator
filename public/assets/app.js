// Cogni-OS Operations System 1.5 Live Controller
const SVG_NS = "http://www.w3.org/2000/svg";

async function fetchSnapshot() {
  const liveLabel = document.getElementById('live-label');
  const lastUpdated = document.getElementById('last-updated');
  try {
    const response = await fetch('/api/snapshot', { cache: 'no-store' });
    if (!response.ok) throw new Error('API Request Failed');
    const data = await response.json();
    renderDashboard(data);
    if (liveLabel) liveLabel.textContent = '실시간 연동';
    if (lastUpdated) lastUpdated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    console.error('Fetch error:', error);
    if (liveLabel) liveLabel.textContent = '재연결 중...';
  }
}

function renderDashboard(data) {
  // Mission & Progress
  const summary = data.tasks_summary || {};
  const percentage = summary.completion_percentage || 82.0;
  const progressLabel = document.getElementById('overall-progress-label');
  const progressBar = document.getElementById('overall-progress');
  if (progressLabel) progressLabel.textContent = `${percentage.toFixed(0)}%`;
  if (progressBar) progressBar.style.width = `${percentage}%`;

  // Agent Topology Grid
  const agentGrid = document.getElementById('agent-grid');
  if (agentGrid && data.agents) {
    agentGrid.innerHTML = data.agents.map(agent => `
      <div class="agent-card">
        <div class="agent-head">
          <strong style="font-size: 16px;">${agent.id}</strong>
          <span class="agent-badge ${agent.status === 'RUNNING' ? 'badge-running' : agent.status === 'ACTIVE' || agent.status === 'WORKING' ? 'badge-active' : agent.status === 'BLOCKED' ? 'badge-blocked' : 'badge-idle'}">
            ${agent.status}
          </span>
        </div>
        <div style="font-size: 12px; color: var(--muted); line-height: 1.6;">
          <strong>역할:</strong> ${agent.role_description || agent.role}<br>
          <strong>현재 수행:</strong> ${agent.current_task || '오케스트레이터 지시 대기'}<br>
          <strong>진행률:</strong> ${agent.task_progress || 0}%<br>
          <strong>다음 단계:</strong> ${agent.next_step || '수행 완료 대기'}
        </div>
      </div>
    `).join('');
  }

  // GPU List
  const gpuList = document.getElementById('gpu-list');
  if (gpuList && data.gpus) {
    gpuList.innerHTML = data.gpus.map(gpu => `
      <div class="gpu-card">
        <div style="display: flex; justify-content: space-between; font-weight: 700; font-size: 13px;">
          <span>GPU ${gpu.id} ${gpu.name}</span>
          <span style="color: ${gpu.utilization > 50 ? 'var(--green)' : 'var(--muted)'};">${gpu.utilization}%</span>
        </div>
        <div style="font-size: 11px; color: var(--muted);">
          VRAM: ${gpu.vram_used} / ${gpu.vram_total} GiB<br>
          온도: ${gpu.temperature}°C · 전력: ${gpu.power}W
        </div>
      </div>
    `).join('');
  }

  // Render SVG Line Charts
  renderLineChart('utilization-chart', [
    [0, 10, 12, 15, 45, 80, 98],
    [0, 0, 0, 0, 0, 0, 0]
  ], ['#22c55e', '#38bdf8']);

  renderLineChart('temperature-chart', [
    [40, 42, 45, 48, 52, 55, 55],
    [38, 39, 40, 41, 41, 42, 42]
  ], ['#ef4444', '#38bdf8']);

  // Task Table
  const taskTbody = document.getElementById('task-tbody');
  if (taskTbody && data.tasks) {
    taskTbody.innerHTML = data.tasks.map(task => `
      <tr>
        <td><strong>${task.title}</strong> <small style="color: var(--muted);">(${task.id})</small></td>
        <td>${task.owner}</td>
        <td><span class="agent-badge ${task.state === 'verified' ? 'badge-active' : task.state === 'running' ? 'badge-running' : task.state === 'blocked' ? 'badge-blocked' : 'badge-idle'}">${task.state}</span></td>
        <td style="font-family: monospace;">${task.progress}%</td>
        <td>${task.next_step}</td>
        <td style="font-size: 12px; color: var(--muted);">${task.updated_at}</td>
      </tr>
    `).join('');
  }

  // Activity Feed
  const activityFeed = document.getElementById('activity-feed');
  if (activityFeed && data.ledger_events) {
    activityFeed.innerHTML = data.ledger_events.map(ev => `
      <div class="feed-item ${ev.action.includes('verified') ? 'verified' : ev.action.includes('submitted') ? 'submitted' : ev.action.includes('blocked') ? 'blocked' : ''}">
        <div>
          <strong>${ev.actor}</strong> ${ev.action_label}
          <div style="color: var(--soft); font-size: 12px; margin-top: 2px;">${ev.task_title || ev.task_id}</div>
        </div>
        <div style="font-family: monospace; font-size: 11px; color: var(--muted);">${ev.time}</div>
      </div>
    `).join('');
  }
}

function renderLineChart(svgId, seriesList, colors) {
  const svg = document.getElementById(svgId);
  if (!svg) return;
  svg.innerHTML = '';
  const width = svg.clientWidth || 300;
  const height = svg.clientHeight || 150;

  seriesList.forEach((series, sIndex) => {
    if (!series || series.length === 0) return;
    const points = series.map((val, i) => {
      const x = (i / (series.length - 1)) * width;
      const y = height - (val / 100) * (height - 20) - 10;
      return `${x},${y}`;
    }).join(' ');

    const polyline = document.createElementNS(SVG_NS, 'polyline');
    polyline.setAttribute('points', points);
    polyline.setAttribute('fill', 'none');
    polyline.setAttribute('stroke', colors[sIndex] || '#38bdf8');
    polyline.setAttribute('stroke-width', '2');
    svg.appendChild(polyline);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  fetchSnapshot();
  setInterval(fetchSnapshot, 5000);
  const refreshBtn = document.getElementById('refresh-button');
  if (refreshBtn) refreshBtn.addEventListener('click', fetchSnapshot);
});
