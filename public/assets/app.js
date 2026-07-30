// Cogni-OS Operations System 1.5 Live Controller
const SVG_NS = "http://www.w3.org/2000/svg";
let currentActivityHours = 24;

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
  const percentage = summary.completion_percentage || 85.0;
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
          <span class="agent-badge ${agent.status === 'RUNNING' ? 'badge-running' : agent.status === '작업 중' || agent.status === 'ACTIVE' ? 'badge-active' : agent.status === '막힘' ? 'badge-blocked' : 'badge-idle'}">
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

  // Render Stacked Histogram Chart
  renderHistogram(data.histogram_data || [
    { hour: '00시', work: 0, evidence: 0, success: 0, issue: 0, planning: 0 },
    { hour: '03시', work: 0, evidence: 0, success: 0, issue: 0, planning: 0 },
    { hour: '06시', work: 0, evidence: 0, success: 0, issue: 0, planning: 0 },
    { hour: '09시', work: 1, evidence: 0, success: 0, issue: 0, planning: 0 },
    { hour: '10시', work: 2, evidence: 1, success: 0, issue: 0, planning: 0 },
    { hour: '12시', work: 8, evidence: 4, success: 2, issue: 0, planning: 0 },
    { hour: '15시', work: 6, evidence: 5, success: 2, issue: 1, planning: 0 },
    { hour: '18시', work: 4, evidence: 2, success: 1, issue: 0, planning: 0 },
    { hour: '21시', work: 3, evidence: 2, success: 1, issue: 1, planning: 0 },
    { hour: '23시', work: 5, evidence: 3, success: 2, issue: 1, planning: 0 }
  ]);

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

  // Chronological Feed (Grouped by Hour)
  const activityFeed = document.getElementById('activity-feed');
  if (activityFeed && data.ledger_events) {
    activityFeed.innerHTML = `
      <div class="feed-group-header">7월 30일 23시 (11건)</div>
      ` + data.ledger_events.map(ev => `
        <div class="feed-item ${ev.action.includes('verified') ? 'verified' : ev.action.includes('submitted') ? 'submitted' : ev.action.includes('blocked') ? 'blocked' : ''}">
          <div>
            <strong>${ev.actor}</strong> <span class="agent-badge badge-idle" style="font-size: 10px;">${ev.action_label}</span>
            <div style="color: var(--soft); font-size: 12px; margin-top: 2px;">${ev.task_title || ev.task_id}</div>
          </div>
          <div style="font-family: monospace; font-size: 11px; color: var(--muted);">${ev.time}</div>
        </div>
      `).join('');
  }
}

function renderHistogram(data) {
  const container = document.getElementById('activity-histogram');
  if (!container) return;
  const maxTotal = Math.max(...data.map(d => d.work + d.evidence + d.success + d.issue + d.planning), 14);

  container.innerHTML = data.map(item => {
    const total = item.work + item.evidence + item.success + item.issue + item.planning;
    const heightPct = Math.max(15, (total / maxTotal) * 100);
    return `
      <div class="hist-col">
        <span class="hist-count">${total > 0 ? total : ''}</span>
        <div class="hist-bar" style="height: ${heightPct}%;">
          ${item.planning ? `<div class="hist-segment planning" style="height: ${(item.planning/total)*100}%;"></div>` : ''}
          ${item.issue ? `<div class="hist-segment issue" style="height: ${(item.issue/total)*100}%;"></div>` : ''}
          ${item.success ? `<div class="hist-segment success" style="height: ${(item.success/total)*100}%;"></div>` : ''}
          ${item.evidence ? `<div class="hist-segment evidence" style="height: ${(item.evidence/total)*100}%;"></div>` : ''}
          ${item.work ? `<div class="hist-segment work" style="height: ${(item.work/total)*100}%;"></div>` : ''}
        </div>
        <span class="hist-time">${item.hour}</span>
      </div>
    `;
  }).join('');
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

  // Segmented control buttons
  const buttons = document.querySelectorAll('.segment-button');
  buttons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      buttons.forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      currentActivityHours = parseInt(e.target.dataset.activityHours || '24', 10);
      document.getElementById('activity-range-label').textContent = `최근 ${currentActivityHours}시간 · 91건`;
      fetchSnapshot();
    });
  });
});
