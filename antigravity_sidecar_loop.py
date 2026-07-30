"""
Antigravity Envelope Fetcher & Dispatcher (Genuine Model Integration).

This script ONLY fetches pending task envelopes from C:\\comunity via room.ps1 and presents
the envelope, task brief, and input evidence to Antigravity (the AI model) for genuine
reasoning, critique, and decision. It NEVER hardcodes automated dummy votes.
"""
import os
import sys
import json
import subprocess
from pathlib import Path

WORKSPACE = r"C:\comunity"
ROOM_PS1 = os.path.join(WORKSPACE, "orchestrator", "room.ps1")

def run_room_cmd(*args):
    cmd = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", ROOM_PS1, *args, "-WorkspaceRoot", WORKSPACE
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return res.stdout.strip(), res.returncode

def fetch_next_task():
    """Fetch pending task envelope for antigravity from room.ps1 without auto-voting."""
    out, code = run_room_cmd("next", "-Agent", "antigravity")
    if not out or out.startswith("QUEUE_EMPTY"):
        return None, None

    lines = [l.strip() for l in out.splitlines() if l.strip()]
    message_path = None
    envelope_data = {}

    for line in lines:
        if line.startswith("ROOM_MESSAGE_PATH:"):
            message_path = line.split(":", 1)[1].strip()
        elif line.startswith("{") and line.endswith("}"):
            try:
                envelope_data = json.loads(line)
            except Exception:
                pass

    return message_path, envelope_data

def submit_task_response(message_path: str):
    """Submit response after Antigravity has written the output_path."""
    out_msg, code = run_room_cmd("submit", "-Agent", "antigravity", "-MessagePath", message_path)
    return out_msg

def main():
    msg_path, env = fetch_next_task()
    if not msg_path:
        print("STATUS: QUEUE_EMPTY (No pending task envelopes for antigravity)")
        return

    print("=" * 80)
    print(f"=== PENDING TASK ENVELOPE FETCHED FOR MODEL REVIEW ===")
    print(f"Message Path: {msg_path}")
    print(f"Envelope Data:\n{json.dumps(env, indent=2)}")
    print("=" * 80)

if __name__ == "__main__":
    main()
