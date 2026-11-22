"""False-positive regressions found by scanning real startup codebases.

Each case pairs a project that *has* the control (the gap must not fire) with
one that lacks it (the gap must still fire), so precision gains never cost
recall.
"""

from __future__ import annotations

from pathlib import Path

from scanner import scan_project
from scanner.analyzers._base import AnalyzerContext
from scanner.analyzers.adversarial_robustness import analyze_adversarial_robustness
from scanner.analyzers.data_pipeline import analyze_data_pipeline
from scanner.founder_triage import build_founder_triage


def _ctx(files: dict[str, str]) -> AnalyzerContext:
    return AnalyzerContext(files=files, file_list=list(files))


def _gap_ids(result) -> set[str]:
    return {f.id for f in result.findings if f.compliance_impact == "gap"}


# ---------------------------------------------------------------------------
# Input validation: TypeScript / JS / other Python validators count
# ---------------------------------------------------------------------------

_TS_ROUTE = (
    'import OpenAI from "openai";\n'
    'import express from "express";\n'
    "const app = express();\n"
    'app.post("/chat", async (req, res) => {\n'
    "  const body = ChatRequest.parse(req.body);\n"
    "  const client = new OpenAI();\n"
    '  const out = await client.chat.completions.create({ model: "gpt-4o", messages: body.messages });\n'
    "  res.json(out);\n"
    "});\n"
)


def test_zod_schema_counts_as_input_validation() -> None:
    files = {
        "src/schema.ts": 'import { z } from "zod";\nexport const ChatRequest = z.object({ messages: z.array(z.any()).max(50) });\n',
        "src/server.ts": _TS_ROUTE,
    }
    assert "ar-no-input-validation" not in _gap_ids(analyze_adversarial_robustness(_ctx(files)))


def test_missing_validation_on_web_endpoint_still_flagged() -> None:
    files = {"src/server.ts": _TS_ROUTE.replace("ChatRequest.parse(req.body)", "req.body")}
    assert "ar-no-input-validation" in _gap_ids(analyze_adversarial_robustness(_ctx(files)))


# ---------------------------------------------------------------------------
# Endpoint-only gaps do not fire for CLIs, libraries and batch jobs
# ---------------------------------------------------------------------------

_CLI_TOOL = (
    "import argparse\n"
    "import anthropic\n\n"
    "def main() -> None:\n"
    "    parser = argparse.ArgumentParser()\n"
    "    parser.add_argument('file')\n"
    "    args = parser.parse_args()\n"
    "    client = anthropic.Anthropic()\n"
    "    text = open(args.file).read()\n"
    "    print(client.messages.create(model='claude-sonnet-4-5', max_tokens=500,\n"
    "          messages=[{'role': 'user', 'content': text}]))\n"
)


def test_cli_tool_has_no_endpoint_rate_limit_or_validation_gaps() -> None:
    gaps = _gap_ids(analyze_adversarial_robustness(_ctx({"summarize.py": _CLI_TOOL})))
    assert "ar-no-rate-limiting" not in gaps
    assert "ar-no-input-validation" not in gaps


def test_web_api_without_rate_limit_still_flagged() -> None:
    api = (
        "from fastapi import FastAPI\nimport anthropic\n\napp = FastAPI()\n\n"
        "@app.post('/summarize')\ndef summarize(text: str):\n"
        "    return anthropic.Anthropic().messages.create(model='m', max_tokens=10,\n"
        "        messages=[{'role': 'user', 'content': text}])\n"
    )
    assert "ar-no-rate-limiting" in _gap_ids(analyze_adversarial_robustness(_ctx({"app.py": api})))


# ---------------------------------------------------------------------------
# Output validation: structured outputs count
# ---------------------------------------------------------------------------


def test_structured_outputs_count_as_output_validation() -> None:
    app = (
        "from openai import OpenAI\nfrom pydantic import BaseModel\n\n"
        "class Answer(BaseModel):\n    text: str\n    sources: list[str]\n\n"
        "def ask(q: str) -> Answer:\n"
        "    client = OpenAI()\n"
        "    resp = client.responses.parse(model='gpt-4o', input=q, text_format=Answer)\n"
        "    return resp.output_parsed\n"
    )
    assert "ar-no-output-validation" not in _gap_ids(analyze_adversarial_robustness(_ctx({"rag.py": app})))


def test_vercel_ai_sdk_generate_object_counts_as_output_validation() -> None:
    app = (
        'import { generateObject } from "ai";\nimport { openai } from "@ai-sdk/openai";\n'
        'import { z } from "zod";\n'
        "export async function classify(text: string) {\n"
        '  const { object } = await generateObject({ model: openai("gpt-4o"), schema: z.object({ label: z.string() }), prompt: text });\n'
        "  return object;\n}\n"
    )
    assert "ar-no-output-validation" not in _gap_ids(analyze_adversarial_robustness(_ctx({"lib/classify.ts": app})))


def test_raw_llm_text_returned_unchecked_still_flagged() -> None:
    app = (
        "from openai import OpenAI\n\n"
        "def ask(q: str) -> str:\n"
        "    return OpenAI().chat.completions.create(model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': q}]).choices[0].message.content\n"
    )
    assert "ar-no-output-validation" in _gap_ids(analyze_adversarial_robustness(_ctx({"bot.py": app})))


# ---------------------------------------------------------------------------
# Prompt-injection / content-safety guards: hosted moderation & guardrail services
# ---------------------------------------------------------------------------


def test_openai_moderation_counts_as_guard() -> None:
    app = (
        "from openai import OpenAI\nclient = OpenAI()\n\n"
        "def safe_reply(user_text: str) -> str:\n"
        "    if client.moderations.create(model='omni-moderation-latest', input=user_text).results[0].flagged:\n"
        "        return 'Sorry, I cannot help with that.'\n"
        "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': user_text}]).choices[0].message.content\n"
    )
    assert "ar-no-prompt-guards" not in _gap_ids(analyze_adversarial_robustness(_ctx({"bot.py": app})))


def test_bedrock_guardrail_counts_as_guard() -> None:
    app = (
        "import boto3\nimport anthropic\n\nbr = boto3.client('bedrock-runtime')\n\n"
        "def check(text: str):\n"
        "    return br.apply_guardrail(guardrailIdentifier='gr-123', guardrailVersion='1', source='INPUT',\n"
        "                              content=[{'text': {'text': text}}])\n"
    )
    assert "ar-no-prompt-guards" not in _gap_ids(analyze_adversarial_robustness(_ctx({"guard.py": app})))


# ---------------------------------------------------------------------------
# Art. 10 training-data gaps need training code, not just pandas
# ---------------------------------------------------------------------------


def test_pandas_without_training_raises_no_art10_gaps() -> None:
    files = {
        "report.py": (
            "import pandas as pd\nfrom openai import OpenAI\n\n"
            "def summarize(csv_path: str) -> str:\n"
            "    df = pd.read_csv(csv_path)\n"
            "    return OpenAI().chat.completions.create(model='gpt-4o', messages=[{'role': 'user',\n"
            "        'content': df.head().to_string()}]).choices[0].message.content\n"
        )
    }
    gaps = _gap_ids(analyze_data_pipeline(_ctx(files)))
    assert "dp-no-versioning" not in gaps
    assert "dp-no-quality-checks" not in gaps


def test_training_pipeline_without_versioning_still_flagged() -> None:
    files = {
        "train.py": (
            "import pandas as pd\nfrom sklearn.linear_model import LogisticRegression\n"
            "from sklearn.model_selection import train_test_split\n\n"
            "df = pd.read_csv('data.csv')\nX_train, X_test, y_train, y_test = train_test_split(df[['a']], df['y'])\n"
            "model = LogisticRegression().fit(X_train, y_train)\n"
        )
    }
    gaps = _gap_ids(analyze_data_pipeline(_ctx(files)))
    assert "dp-no-versioning" in gaps
    assert "dp-no-quality-checks" in gaps


# ---------------------------------------------------------------------------
# Founder brief: provider-only paperwork is not a deployer's to-do
# ---------------------------------------------------------------------------

_DEPLOYER_APP = {
    "app.py": (
        "from fastapi import FastAPI\nfrom openai import OpenAI\n\napp = FastAPI()\nclient = OpenAI()\n\n"
        "@app.post('/chat')\ndef chat(message: str) -> dict:\n"
        "    reply = client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': message}])\n"
        "    return {'reply': reply.choices[0].message.content}\n"
    ),
    "README.md": "# Support bot\n\nAnswers customer questions.\n",
}


def test_deployer_brief_leaves_out_provider_only_paperwork(tmp_path: Path) -> None:
    for name, body in _DEPLOYER_APP.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    result = scan_project(tmp_path)
    assert "deployer" in result.inferred_roles and "provider" not in result.inferred_roles
    triage = build_founder_triage(result)
    titles = [i.title for b in (triage.ship_now, triage.enterprise_deals, triage.later_2027) for i in b]
    assert not any("substantial-modification" in t for t in titles), titles
    assert not any(t.startswith("README missing sections") for t in titles), titles
    assert triage.summary_counts.get("not_for_your_role", 0) >= 1
    assert "only to AI providers" in triage.brief_markdown


def test_explicit_provider_role_keeps_provider_paperwork(tmp_path: Path) -> None:
    for name, body in _DEPLOYER_APP.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    triage = build_founder_triage(scan_project(tmp_path, role="provider"))
    assert triage.summary_counts.get("not_for_your_role", 0) == 0


# ---------------------------------------------------------------------------
# Second-round decoys (surfaced once the first round cleared the cap of 3 hits)
# ---------------------------------------------------------------------------


def _secret_gaps(files: dict[str, str]) -> list[str]:
    from scanner.analyzers.security_controls import analyze_security_controls

    return [f.file_path for f in analyze_security_controls(_ctx(files)).findings if f.id.startswith("sec-hardcoded")]


def test_ui_validation_message_is_not_a_password() -> None:
    files = {"src/pages/Login.tsx": "if (!password) errors.password = 'Password is required';\n"}
    assert _secret_gaps(files) == []


def test_identifier_shaped_value_is_not_a_secret() -> None:
    files = {"app/models.py": 'security_hub_api_key = "security_hub_api_key"\n'}
    assert _secret_gaps(files) == []


def test_real_looking_hardcoded_key_is_still_flagged() -> None:
    files = {"app/settings.py": 'api_key = "k9Xq2Lm7Rt4Vb8Nc1Zp5"\n'}
    assert _secret_gaps(files) == ["app/settings.py"]


def test_comment_mentioning_trajectory_is_not_monitoring() -> None:
    from scanner.analyzers.runtime_drift import analyze_runtime_drift

    files = {"scripts/report.ts": "// Score trajectory\nexport const score = 1;\n"}
    ids = {f.id for f in analyze_runtime_drift(_ctx(files)).findings}
    assert "rd-behavior-no-baseline" not in ids
