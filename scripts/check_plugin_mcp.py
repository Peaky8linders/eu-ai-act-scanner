#!/usr/bin/env python3
"""Start the Claude Code plugin's MCP server the way Claude Code does, and check it answers.

Reads the server entry from ``.claude-plugin/plugin.json``, replaces
``${CLAUDE_PLUGIN_ROOT}`` with this checkout (forward slashes, as Claude Code
substitutes paths on Windows), starts the command from an empty working
directory, performs the MCP ``initialize`` handshake over stdio, lists the
tools and compares them with the README's tool count.

CI runs it on Linux, macOS and Windows with a cold uv cache, so the reported
time to the ``initialize`` answer is close to a founder's first start. Claude
Code gives a server 30 seconds to start by default (``MCP_TIMEOUT``); a slower
first start is reported as a warning, not a failure, because CI network speed
is not the user's.

Standard library only, so it needs no install:
``uv run --no-project scripts/check_plugin_mcp.py``.
"""

from __future__ import annotations

import json
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_TOOLS = {"founder_triage", "scan_project"}
CLAUDE_CODE_STARTUP_LIMIT_S = 30.0
TIMEOUT_S = 600.0
PROTOCOL_VERSION = "2025-06-18"


def server_command(root: Path = ROOT) -> list[str]:
    """The plugin's MCP server command, with ``${CLAUDE_PLUGIN_ROOT}`` filled in."""
    manifest = json.loads((root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    server = manifest["mcpServers"][manifest["name"]]
    parts = [server["command"], *server.get("args", [])]
    return [part.replace("${CLAUDE_PLUGIN_ROOT}", root.as_posix()) for part in parts]


def claimed_tool_count(root: Path = ROOT) -> int:
    """The tool count the README advertises (tests/test_public_claims.py ties it to the code)."""
    match = re.search(r"\*\*(\d+) MCP Tools:\*\*", (root / "README.md").read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit("README.md no longer states the MCP tool count")
    return int(match.group(1))


def check_tools(names: list[str], expected: int) -> list[str]:
    """Problems with the listed tools; empty when they match the plugin's promise."""
    problems: list[str] = []
    missing = REQUIRED_TOOLS - set(names)
    if missing:
        problems.append(f"missing tools: {sorted(missing)}")
    if len(names) != expected:
        problems.append(f"{len(names)} tools listed, README claims {expected}")
    return problems


class _Server:
    """A started stdio MCP server with newline-delimited JSON-RPC in and out."""

    def __init__(self, command: list[str], cwd: str) -> None:
        self.proc = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        self._lines: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def response(self, request_id: int, deadline: float) -> dict[str, Any]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no answer to request {request_id} within {TIMEOUT_S:.0f}s")
            line = self._lines.get(timeout=remaining)
            if line is None:
                raise RuntimeError(f"server exited (code {self.proc.poll()}) before answering {request_id}")
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                raise RuntimeError(f"server wrote a non-JSON line to stdout: {line.strip()[:200]}") from None
            if isinstance(message, dict) and message.get("id") == request_id:
                if "error" in message:
                    raise RuntimeError(f"request {request_id} failed: {message['error']}")
                result = message.get("result")
                return result if isinstance(result, dict) else {}

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def main() -> int:
    command = server_command()
    expected = claimed_tool_count()
    print("starting:", " ".join(command), flush=True)
    started = time.monotonic()
    deadline = started + TIMEOUT_S
    with tempfile.TemporaryDirectory() as empty_cwd:
        server = _Server(command, cwd=empty_cwd)
        try:
            server.send({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "antifragile-harness-ci", "version": "1"},
                },
            })
            info = server.response(1, deadline)
            startup = time.monotonic() - started
            name = info.get("serverInfo", {}).get("name")
            version = info.get("serverInfo", {}).get("version")
            print(f"initialized: {name} {version} in {startup:.1f}s", flush=True)
            if startup > CLAUDE_CODE_STARTUP_LIMIT_S:
                print(
                    f"::warning::first start took {startup:.0f}s, over Claude Code's default "
                    f"{CLAUDE_CODE_STARTUP_LIMIT_S:.0f}s MCP startup limit",
                    flush=True,
                )
            server.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

            names: list[str] = []
            cursor: str | None = None
            request_id = 2
            while True:
                params = {"cursor": cursor} if cursor else {}
                server.send({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params})
                page = server.response(request_id, deadline)
                names += [tool["name"] for tool in page.get("tools", [])]
                cursor = page.get("nextCursor")
                request_id += 1
                if not cursor:
                    break
        finally:
            server.close()

    print(f"tools ({len(names)}): {', '.join(sorted(names))}")
    problems = check_tools(names, expected)
    for problem in problems:
        print(f"::error::{problem}")
    leftovers = [p.name for p in (ROOT / "build", *ROOT.glob("*.egg-info")) if p.exists()]
    print("build output left in the plugin folder:", ", ".join(leftovers) or "none")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
