"""Adversarial / prompt-injection regression suite (EU AI Act Art. 15(3)-(4)).

Two directions are tested, because a scanner can fail either way:

* **detection** — injected/exfiltrating patterns in scanned code must produce a
  finding (`pm-open-exec`, `pm-prompt-as-control`, `lt-trifecta-violation`);
* **precision** — the same words in prose, fixtures or a non-LLM module must
  *not* produce one. Over-flagging trains users to ignore the report, which is
  its own Art. 15 failure.

Each case is a synthetic project built in ``tmp_path`` and fed to the analyzer
through a real ``AnalyzerContext`` — the same path a scan uses.
"""

from __future__ import annotations

from scanner.analyzers import AnalyzerContext
from scanner.analyzers.adversarial_robustness import analyze_adversarial_robustness
from scanner.analyzers.lethal_trifecta import analyze_lethal_trifecta
from scanner.analyzers.privilege_minimization import analyze_privilege_minimization


def _ctx(files: dict[str, str]) -> AnalyzerContext:
    return AnalyzerContext(
        files=files,
        file_list=sorted(files),
        binary_files={},
        languages={},
    )


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


# ---------------------------------------------------------------------------
# Prompt injection: guards are code, not prose
# ---------------------------------------------------------------------------


def test_prompt_injection_prose_is_not_a_guard() -> None:
    """A README that *describes* prompt injection is not an injection guard."""
    result = analyze_adversarial_robustness(_ctx({
        "README.md": (
            "# App\n\nWe care about prompt injection and jailbreak detection.\n"
            "Guardrails are on the roadmap.\n"
        ),
        "src/app.py": "import openai\nclient = openai.OpenAI()\n",
    }))
    assert "ar-prompt-guards" not in _ids(result)


def test_prompt_guard_code_is_detected() -> None:
    result = analyze_adversarial_robustness(_ctx({
        "src/app.py": (
            "import openai\n\n"
            "def detect_prompt_injection(user_text: str) -> bool:\n"
            "    return 'ignore previous instructions' in user_text.lower()\n"
        ),
    }))
    assert "ar-prompt-guards" in _ids(result)


def test_adversarial_test_reference_is_detected_in_code() -> None:
    result = analyze_adversarial_robustness(_ctx({
        "src/model.py": "import torch\n\nclass Net(torch.nn.Module):\n    pass\n",
        "tests/test_robustness.py": "def test_adversarial_perturbation_blocks_output():\n    assert True\n",
    }))
    assert "ar-adversarial-patterns" in _ids(result)


# ---------------------------------------------------------------------------
# Prompt-as-control antipattern vs. an architectural control
# ---------------------------------------------------------------------------


def test_prompt_restriction_as_control_is_flagged() -> None:
    result = analyze_privilege_minimization(_ctx({
        "src/agent.py": (
            "import openai\n\n"
            "SYSTEM = 'Never delete files and do not send email to anyone.'\n"
        ),
    }))
    assert "pm-prompt-as-control" in _ids(result)


def test_prompt_restriction_in_test_fixture_is_ignored() -> None:
    """Fixtures embed prompts by design — they are not the shipped control."""
    result = analyze_privilege_minimization(_ctx({
        "tests/test_agent_prompt.py": (
            "import openai\n\n"
            "def test_prompt():\n"
            "    prompt = 'Never delete files and do not send email to anyone.'\n"
        ),
    }))
    assert "pm-prompt-as-control" not in _ids(result)


# ---------------------------------------------------------------------------
# Model output reaching a shell / interpreter
# ---------------------------------------------------------------------------


def test_model_output_executed_in_shell_is_flagged() -> None:
    result = analyze_privilege_minimization(_ctx({
        "src/runner.py": (
            "import openai, subprocess\n\n"
            "def run(client, task):\n"
            "    plan = client.chat.completions.create(model='gpt-4o', messages=[task])\n"
            "    subprocess.run(plan.choices[0].message.content, shell=True)\n"
        ),
    }))
    assert "pm-open-exec" in _ids(result)


def test_shell_use_outside_llm_modules_is_not_flagged() -> None:
    result = analyze_privilege_minimization(_ctx({
        "src/build_tool.py": "import subprocess\nsubprocess.run(['make'], check=True)\n",
    }))
    assert "pm-open-exec" not in _ids(result)


# ---------------------------------------------------------------------------
# Lethal trifecta (untrusted input + sensitive data + autonomous action)
# ---------------------------------------------------------------------------

_TRIFECTA_FILE = (
    "import boto3, smtplib\n"
    "from fastapi import FastAPI, Request\n"
    "app = FastAPI()\n\n"
    "def send_email(to, body):\n"
    "    with smtplib.SMTP('localhost') as mailer:\n"
    "        mailer.send_message(body)\n\n"
    "@app.post('/agent')\n"
    "async def handler(request: Request):\n"
    "    payload = await request.json()\n"
    "    client = boto3.client('secretsmanager')\n"
    "    secret = client.get_secret_value(SecretId='prod/db')\n"
    "    send_email(payload['to'], secret)\n"
)


def test_lethal_trifecta_violation_without_oversight_gate() -> None:
    result = analyze_lethal_trifecta(_ctx({"src/agent.py": _TRIFECTA_FILE}))
    assert "lt-trifecta-violation" in _ids(result)


def test_lethal_trifecta_gate_moves_finding_to_positive() -> None:
    gated = _TRIFECTA_FILE.replace(
        "    send_email(payload['to'], secret)\n",
        "    if not human_approval_required(payload):\n"
        "        return {'status': 'awaiting_approval'}\n"
        "    send_email(payload['to'], secret)\n",
    )
    result = analyze_lethal_trifecta(_ctx({"src/agent.py": gated}))
    ids = _ids(result)
    assert "lt-trifecta-with-gate" in ids
    assert "lt-trifecta-violation" not in ids


def test_lethal_trifecta_in_test_fixture_is_not_runtime_evidence() -> None:
    """A test that builds a trifecta to exercise the detector is not an agent
    invocation path. Counting it credited the project with oversight it does
    not have (and lowered the score of the dimension the fixture landed on)."""
    for path in ("tests/test_agent_flow.py", "src/agent_test.py", "tests/conftest.py"):
        assert analyze_lethal_trifecta(_ctx({path: _TRIFECTA_FILE})).findings == []
