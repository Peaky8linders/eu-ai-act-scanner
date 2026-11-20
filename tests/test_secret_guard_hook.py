"""The opt-in secret-guard hook: real Claude Code schema, real blocking behaviour.

The original template used a made-up schema (``{"hooks": [{"event", "pattern",
"command"}]}``). Claude Code ignores ``pattern``, so had it been loaded the
``Write|Edit`` entry would have run ``exit 2`` on every single file write.
These tests pin the corrected template and drive the guard script exactly the
way Claude Code does: tool-call JSON on stdin, exit code 2 to block.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.analyzers._base import AnalyzerContext
from scanner.analyzers.claude_code_security import analyze_claude_code_security

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOK_JSON = REPO_ROOT / "hooks" / "sensitive-data-guard.json"
HOOK_SCRIPT = REPO_ROOT / "hooks" / "sensitive_data_guard.py"

# Built by concatenation so this test file never holds a credential-shaped literal.
FAKE_OPENAI_KEY = "sk-" + "proj-" + "Q7v2Lm9Xr4Tz8Kb1Nw6Hc3Pd5Fg0Js2A"
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPL3"


def _run_guard(payload: dict, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=30,
        check=False,
    )


class TestTemplateSchema:
    def test_uses_claude_code_event_map_schema(self) -> None:
        data = json.loads(HOOK_JSON.read_text(encoding="utf-8"))
        pre = data["hooks"]["PreToolUse"]
        assert isinstance(pre, list) and pre
        for entry in pre:
            assert "matcher" in entry
            for hook in entry["hooks"]:
                assert hook["type"] == "command"
                assert "sensitive_data_guard.py" in hook["command"]
                # No invented keys that Claude Code would silently ignore.
                assert "pattern" not in hook and "pattern" not in entry

    def test_no_unconditional_block(self) -> None:
        raw = HOOK_JSON.read_text(encoding="utf-8")
        assert "exit 2" not in raw


class TestGuardBehaviour:
    @pytest.mark.parametrize("name", [".env", ".env.production", "server.pem", "tls.key", "id_ed25519"])
    def test_blocks_secret_files(self, name: str) -> None:
        res = _run_guard({"tool_name": "Write", "tool_input": {"file_path": f"/repo/{name}", "content": "X=1"}})
        assert res.returncode == 2
        assert "BLOCKED" in res.stderr

    @pytest.mark.parametrize("name", [".env.example", ".env.sample", "app.py", "README.md", "keyboard.py"])
    def test_allows_ordinary_files(self, name: str) -> None:
        res = _run_guard({"tool_name": "Write", "tool_input": {"file_path": f"/repo/{name}", "content": "print('hi')"}})
        assert res.returncode == 0, res.stderr

    def test_blocks_hardcoded_key_in_edit(self) -> None:
        res = _run_guard({
            "tool_name": "Edit",
            "tool_input": {"file_path": "app.py", "old_string": "x", "new_string": f'KEY = "{FAKE_OPENAI_KEY}"'},
        })
        assert res.returncode == 2
        # The key itself is never echoed back in full.
        assert FAKE_OPENAI_KEY not in res.stderr

    def test_blocks_key_in_multiedit(self) -> None:
        res = _run_guard({
            "tool_name": "MultiEdit",
            "tool_input": {"file_path": "cfg.py", "edits": [{"old_string": "a", "new_string": FAKE_AWS_KEY}]},
        })
        assert res.returncode == 2

    def test_allows_placeholder_and_env_lookup(self) -> None:
        content = 'KEY = os.environ["OPENAI_API_KEY"]\nEXAMPLE = "sk-proj-your-key-here-xxxxxxxxxxxx"\n'
        res = _run_guard({"tool_name": "Write", "tool_input": {"file_path": "app.py", "content": content}})
        assert res.returncode == 0, res.stderr

    def test_non_commit_bash_is_allowed(self) -> None:
        res = _run_guard({"tool_name": "Bash", "tool_input": {"command": "ls -la"}})
        assert res.returncode == 0

    def test_malformed_input_fails_open(self) -> None:
        res = subprocess.run(
            [sys.executable, str(HOOK_SCRIPT)], input="not json", capture_output=True, text=True, timeout=30, check=False,
        )
        assert res.returncode == 0

    def test_blocks_commit_that_stages_a_key(self, tmp_path: Path) -> None:
        git = ["git", "-c", "user.email=t@t.invalid", "-c", "user.name=t"]
        if subprocess.run(["git", "--version"], capture_output=True, check=False).returncode != 0:
            pytest.skip("git not available")
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        (tmp_path / "app.py").write_text(f'KEY = "{FAKE_OPENAI_KEY}"\n', encoding="utf-8")
        subprocess.run([*git, "add", "app.py"], cwd=tmp_path, check=True)
        res = _run_guard({"tool_name": "Bash", "tool_input": {"command": "git commit -m wip"}}, cwd=tmp_path)
        assert res.returncode == 2
        assert "staged diff" in res.stderr


class TestAnalyzerRecognisesShippedHook:
    def test_settings_registration_is_credited(self) -> None:
        hooks = json.loads(HOOK_JSON.read_text(encoding="utf-8"))["hooks"]
        settings = json.dumps({"hooks": hooks})
        ctx = AnalyzerContext(
            files={"app.py": "import anthropic\n"},
            file_list=["app.py"],
            agent_config_files={".claude/settings.json": settings},
        )
        result = analyze_claude_code_security(ctx)
        assert "ccs-secret-guard-hook" in {f.id for f in result.findings}

    def test_hook_file_copied_into_claude_hooks_is_credited(self) -> None:
        ctx = AnalyzerContext(
            files={"app.py": "import anthropic\n"},
            file_list=["app.py"],
            agent_config_files={".claude/hooks/sensitive-data-guard.json": HOOK_JSON.read_text(encoding="utf-8")},
        )
        result = analyze_claude_code_security(ctx)
        assert "ccs-secret-guard-hook" in {f.id for f in result.findings}

    def test_legacy_flat_list_schema_still_parsed(self) -> None:
        legacy = json.dumps({"hooks": [{"event": "PreToolUse", "tool": "Write", "command": "block .env secret"}]})
        ctx = AnalyzerContext(
            files={"app.py": "import anthropic\n"},
            file_list=["app.py"],
            agent_config_files={".claude/hooks/legacy.json": legacy},
        )
        result = analyze_claude_code_security(ctx)
        assert "ccs-secret-guard-hook" in {f.id for f in result.findings}
