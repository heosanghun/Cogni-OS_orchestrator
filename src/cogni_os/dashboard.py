"""Read-only local operational dashboard for Cogni-OS."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .errors import CogniError, ConfigurationError
from .workspace import Workspace

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cogni-OS Orchestrator Dashboard</title>
  <style>
    :root {
      color-scheme: dark;
      --ink: #e6edf3;
      --muted: #8b949e;
      --line: #30363d;
      --paper: #161b22;
      --canvas: #0d1117;
      --green: #238636;
      --amber: #d29922;
      --red: #f85149;
      --blue: #58a6ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 14px/1.45 system-ui, -apple-system, sans-serif;
      color: var(--ink);
      background: var(--canvas);
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      min-height: 58px;
      padding: 10px 24px;
      color: white;
      background: #161b22;
      border-bottom: 3px solid var(--blue);
    }
    h1 { margin: 0; font-size: 18px; font-weight: 650; }
    #updated { color: var(--muted); font-size: 12px; }
    main { max-width: 1360px; margin: 0 auto; padding: 20px 24px 40px; }
    .summary {
      display: grid;
      grid-template-columns: repeat(5, minmax(120px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .metric {
      min-height: 78px;
      padding: 14px;
      background: var(--paper);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .metric strong { display: block; font-size: 26px; line-height: 1.1; }
    .metric span { color: var(--muted); font-size: 12px; }
    section { background: var(--paper); border: 1px solid var(--line); border-radius: 8px; }
    .section-head {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      padding: 14px;
      border-bottom: 1px solid var(--line);
    }
    h2 { margin: 0; font-size: 14px; }
    .ledger-ok { color: #3fb950; font-weight: 650; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; min-width: 760px; }
    th, td {
      padding: 10px 14px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid var(--line);
    }
    th { color: var(--muted); background: #0d1117; font-size: 11px; text-transform: uppercase; }
    tr:last-child td { border-bottom: 0; }
    .state { font-weight: 650; }
    .verified { color: #3fb950; }
    .submitted, .running, .claimed { color: var(--blue); }
    .blocked, .rejected { color: var(--red); }
    .pending { color: var(--amber); }
    code { font-family: ui-monospace, "Cascadia Code", monospace; font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <h1 id="workspace">Cogni-OS Orchestrator</h1>
    <div id="updated">Loading</div>
  </header>
  <main>
    <div class="summary" id="summary"></div>
    <section>
      <div class="section-head">
        <h2>Tasks &amp; Evidence Ledger</h2>
        <span class="ledger-ok" id="ledger"></span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Owner</th><th>State</th><th>Attempt</th><th>Title</th><th>Updated</th></tr></thead>
          <tbody id="tasks"></tbody>
        </table>
      </div>
    </section>
  </main>
  <script>
    const esc = (value) => String(value ?? "").replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[c]);
    async function refresh() {
      const response = await fetch("/api/status", {cache: "no-store"});
      const data = await response.json();
      document.getElementById("workspace").textContent = "Cogni-OS: " + data.status.workspace;
      document.getElementById("updated").textContent = new Date().toLocaleString();
      document.getElementById("ledger").textContent =
        `Ledger verified · ${data.status.ledger.events} events`;
      const states = data.status.states;
      const metrics = [
        ["Running", states.running],
        ["Pending", states.pending],
        ["Awaiting verification", states.submitted],
        ["Blocked", states.blocked],
        ["Verified", states.verified + states.archived],
      ];
      document.getElementById("summary").innerHTML = metrics.map(([label, value]) =>
        `<div class="metric"><strong>${value}</strong><span>${esc(label)}</span></div>`
      ).join("");
      document.getElementById("tasks").innerHTML = data.tasks.map(task =>
        `<tr><td><code>${esc(task.id)}</code></td><td>${esc(task.owner)}</td>` +
        `<td><span class="state ${esc(task.state)}">${esc(task.state)}</span></td>` +
        `<td>${task.attempt}</td><td>${esc(task.title)}</td><td>${esc(task.updated_at)}</td></tr>`
      ).join("");
    }
    refresh().catch(error => {
      document.getElementById("updated").textContent = error.message;
    });
    setInterval(() => refresh().catch(() => {}), 3000);
  </script>
</body>
</html>
"""


def _handler(workspace_root: Path) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        def _send_json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            route = urlparse(self.path).path
            try:
                workspace = Workspace(workspace_root)
                if route == "/":
                    body = DASHBOARD_HTML.encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if route == "/api/status":
                    self._send_json(
                        {
                            "status": workspace.status(),
                            "tasks": workspace.list_tasks(),
                        }
                    )
                    return
                if route == "/api/ledger":
                    self._send_json(workspace.ledger.verify())
                    return
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except CogniError as exc:
                self._send_json(
                    {"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR
                )
            except Exception as exc:
                self._send_json(
                    {"error": f"Unhandled dashboard error: {exc}"},
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )

        def log_message(self, format: str, *args: Any) -> None:
            pass

    return DashboardHandler


def serve_dashboard(
    workspace_root: str | Path,
    *,
    host: str = "127.0.0.1",
    port: int = 8484,
) -> None:
    """Serve the read-only operational dashboard."""
    root = Path(workspace_root).resolve()
    Workspace(root)
    server = ThreadingHTTPServer((host, port), _handler(root))
    print(f"Cogni-OS operational dashboard listening at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
