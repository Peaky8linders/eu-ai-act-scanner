"""Tests for the Article 50 transparency analyzer.

Each test encodes *why* the behaviour matters: a transparency scanner that
emits false gaps on unrelated repos trains operators to ignore it, and one
that misses the unmarked-synthetic / emotion-recognition surface fails silently
on the exact 2-Aug-2026-enforceable obligation it exists to catch. The
non-applicable cases are the load-bearing regression guards for the
false-positive half of that contract.
"""

from __future__ import annotations

from scanner.analyzers._base import AnalyzerContext
from scanner.analyzers.article_50_transparency import analyze_article_50_transparency


def _ctx(files: dict[str, str]) -> AnalyzerContext:
    return AnalyzerContext(
        files=files, file_list=list(files.keys()), binary_files={}, languages={}
    )


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


def _impacts(result) -> set[str]:
    return {f.compliance_impact for f in result.findings}


def test_identity_and_graph_shape():
    res = analyze_article_50_transparency(_ctx({}))
    assert res.analyzer_id == "article_50_transparency"
    assert res.label == "Art. 50 Transparency"
    assert res.graph_node_type == "control"
    assert res.graph_icon == "🏷"


def test_backend_only_repo_is_neutral_high_no_false_gaps():
    # No content-generation / chatbot / emotion surface — Art. 50 does not
    # bite, so the analyzer must stay silent (the false-positive guard).
    files = {
        "db.py": (
            "import sqlalchemy\n\n"
            "def get_users(session):\n"
            "    return session.query(User).all()\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    assert res.findings == []
    assert res.score == 80.0
    assert res.file_count == 0


def test_chatbot_without_disclosure_is_50_1_gap():
    files = {
        "bot.py": (
            "import openai\n\n"
            "def reply(user_msg: str) -> str:\n"
            "    resp = openai.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=[{'role': 'user', 'content': user_msg}],\n"
            "    )\n"
            "    return resp.choices[0].message.content\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    gap = next((f for f in res.findings if f.id == "art50-no-ai-disclosure"), None)
    assert gap is not None
    assert gap.article_paragraphs == ["50(1)"]
    assert "content_transparency" in gap.compliance_dimensions
    assert "tr-1" in gap.kb_question_ids


def test_generation_without_marking_is_50_2_gap():
    # Synthetic image generation with no C2PA/watermark → Art. 50(2) gap;
    # importing the SDK must NOT also trip the 50(1) chatbot gap.
    files = {
        "gen.py": (
            "import openai\n\n"
            "def make_image(prompt: str):\n"
            "    return openai.images.generate(model='dall-e-3', prompt=prompt)\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    ids = _ids(res)
    assert "art50-unmarked-synthetic" in ids
    assert "art50-no-ai-disclosure" not in ids
    gap = next(f for f in res.findings if f.id == "art50-unmarked-synthetic")
    assert gap.article_paragraphs == ["50(2)"]


def test_deepfake_without_label_is_50_4_gap():
    files = {
        "swap.py": (
            "import torch\n\n"
            "def run_faceswap(source, target):\n"
            "    model = load_model('inswapper')  # deepfake pipeline\n"
            "    return model.swap(source, target)\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    gap = next((f for f in res.findings if f.id == "art50-unlabelled-deepfake"), None)
    assert gap is not None
    assert gap.article_paragraphs == ["50(4)"]
    assert "ct-3" in gap.kb_question_ids


def test_marked_generation_is_positive_no_gap():
    files = {
        "gen.py": (
            "import openai\n"
            "from c2pa import Builder\n\n"
            "def make_image(prompt: str):\n"
            "    result = openai.images.generate(model='dall-e-3', prompt=prompt)\n"
            "    builder = Builder()\n"
            "    builder.add_watermark(result, label='AI-generated')\n"
            "    return result\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    assert "gap" not in _impacts(res)
    assert "positive" in _impacts(res)
    assert res.score >= 80.0
    assert 0.0 <= res.score <= 100.0


def test_emotion_recognition_without_notice_is_50_3_gap():
    # Before this analyzer there was NO 50(3) detection at all, so the single
    # most likely limited-risk obligation was silently un-scanned.
    files = {
        "cam.py": (
            "from deepface import DeepFace\n\n"
            "def analyze_mood(frame):\n"
            "    # emotion recognition from a webcam frame\n"
            "    return DeepFace.analyze(frame, actions=['emotion'])\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    gap = next((f for f in res.findings if f.id == "art50-emotion-no-notice"), None)
    assert gap is not None
    assert gap.article_paragraphs == ["50(3)"]
    assert "ct-5" in gap.kb_question_ids
    assert "deployer" in gap.applicable_roles


def test_emotion_recognition_with_notice_is_positive_no_gap():
    files = {
        "cam.py": (
            "from deepface import DeepFace\n\n"
            "NOTICE = 'You are being analysed by an emotion recognition system.'\n"
            "def analyze_mood(frame):\n"
            "    show(NOTICE)  # inform the person of the biometric operation\n"
            "    return DeepFace.analyze(frame, actions=['emotion'])\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    ids = _ids(res)
    assert "art50-emotion-no-notice" not in ids
    assert "art50-emotion-notice-present" in ids


def test_plain_sentiment_classifier_does_not_trip_50_3():
    # A text sentiment classifier is NOT an Art. 50(3) emotion-recognition /
    # biometric surface — the false-positive guard.
    files = {
        "nlp.py": (
            "from transformers import pipeline\n\n"
            "clf = pipeline('sentiment-analysis')\n"
            "def score(text: str):\n"
            "    return clf(text)\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    assert "art50-emotion-no-notice" not in _ids(res)


def test_ai_generated_public_interest_text_is_50_4_gap():
    files = {
        "news.py": (
            "import openai\n\n"
            "def write_news_article(topic: str) -> str:\n"
            "    # newsroom auto-journalism\n"
            "    resp = openai.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=[{'role': 'user', 'content': f'Write a news article on {topic}'}],\n"
            "    )\n"
            "    return resp.choices[0].message.content\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    gap = next((f for f in res.findings if f.id == "art50-unlabelled-ai-text"), None)
    assert gap is not None
    assert gap.article_paragraphs == ["50(4)"]
    assert "ct-4" in gap.kb_question_ids


def test_newsroom_without_generation_does_not_trip_50_4_text():
    # A bare "newsroom" identifier with NO LLM/generation surface must not trip
    # the AI-text gap — it is gated on a co-present generation surface.
    files = {
        "models.py": (
            "class Newsroom:\n"
            "    def __init__(self, editor):\n"
            "        self.editor = editor\n"
        )
    }
    res = analyze_article_50_transparency(_ctx(files))
    assert "art50-unlabelled-ai-text" not in _ids(res)
