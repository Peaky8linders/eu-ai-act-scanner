"""Article 50 transparency analyzer — synthetic-content & disclosure detector.

Detects Article 50 transparency conformance deterministically over the scanned
files. Art. 50 is one of the few obligations fully fine-enforceable from
**2 Aug 2026** — the Digital Omnibus (adopted 29 Jun 2026) deferred the
high-risk Annex III regime to 2 Dec 2027 but **left Art. 50 untouched** — and
the June-2026 Transparency Code of Practice points implementers at C2PA content
credentials for the machine-readable marking required by Art. 50(2).

Five transparency obligations are checked, deterministically, over
``ctx.files``:

* **Art. 50(1)** — a natural-person-facing chatbot / assistant must disclose
  it is an AI system (provider).
* **Art. 50(2)** — synthetically generated image/audio/video/text must be
  marked machine-readably (C2PA / watermark / provenance) — provider,
  including GPAI.
* **Art. 50(3)** — an emotion-recognition / biometric-categorisation system
  must notify the natural persons exposed to it (deployer).
* **Art. 50(4)** — deep-fake / synthetic-media content must be labelled, and
  AI-generated text published to inform the public on matters of public
  interest must be disclosed as artificially generated (deployer).

Grounds to the ``content_transparency`` + ``transparency`` KB dimensions. The
detection is aggregate (a disclosure in one file mitigates a generation surface
in another) and conservative: with no content-generation / chatbot / emotion
surface anywhere the analyzer returns a neutral high score and no findings, so a
backend-only repo is never falsely flagged.
"""

from __future__ import annotations

import re

from scanner.analyzers._base import AnalyzerContext, AnalyzerResult, Finding
from scanner.data.role_obligations import ROLE_DEPLOYER, ROLE_PROVIDER

# ─── Surface banks ───────────────────────────────────────────────────────

# A natural-person-facing conversational surface: an LLM chat call or an
# explicit chatbot/assistant construct. Deliberately NOT a bare SDK name
# (``import openai``) — that over-triggers 50(1) on pure image/audio
# generation scripts that only import the provider SDK.
_CHAT_PATTERNS = [
    r"chat\.completions|ChatCompletion|messages\.create|responses\.create",
    r"\b(chatbot|assistant|conversation(al)?)\b",
    r"langchain|llama[-_]?index|llm\.(invoke|chat|complete)",
]

# A synthetic-content generation surface (image / audio / video / text).
_GENERATION_PATTERNS = [
    r"generate_image|images?\.generate|image\.create|text[-_]?to[-_]?image",
    r"dall[-_ ]?e|stable[-_ ]?diffusion|midjourney|flux\.1|imagen",
    r"\btts\b|text[-_]?to[-_]?speech|speech[-_]?synth|elevenlabs|\bsynthes",
    r"text[-_]?to[-_]?video|video\.generate|sora\b|runway(ml)?",
]

# A deep-fake / synthetic-media surface.
_DEEPFAKE_PATTERNS = [
    r"face[-_ ]?swap|faceswap|deep[-_ ]?fake|deepfake",
    r"voice[-_ ]?clon|voice[-_ ]?conversion|speaker[-_ ]?adapt",
    r"lip[-_ ]?sync|wav2lip|sadtalker|\broop\b|reenact",
]

# Machine-readable marking / provenance controls (Art. 50(2)).
_MARKING_PATTERNS = [
    r"\bc2pa\b|content[-_ ]?credential|contentcredentials",
    r"\bsynthid\b",
    r"\bwatermark|invisible[-_ ]?watermark|imwatermark|stegan",
    r"provenance|signed[-_ ]?manifest|content[-_ ]?authenticity",
]

# Explicit AI-interaction / AI-generated disclosure strings (Art. 50(1)/50(4)).
_DISCLOSURE_PATTERNS = [
    r"you\s+are\s+(chatting|talking|interacting|speaking)\s+with\s+an?\s+ai",
    r"\bai[-\s]?generated\b|generated\s+by\s+ai|made\s+by\s+ai",
    r"this\s+is\s+an?\s+ai|i\s+am\s+an?\s+ai|not\s+a\s+human",
    r"ai\s+(assistant|disclosure|disclaimer)|automated\s+assistant",
    r"synthetic\s+media|artificially\s+generated",
]

# An emotion-recognition / biometric-categorisation surface (Art. 50(3)).
# Deliberately specific model/dataset/library names so a generic "sentiment"
# text classifier (out of Art. 50(3) scope) does not over-trigger.
_EMOTION_BIOMETRIC_PATTERNS = [
    r"emotion[-_ ]?recogni|affect(ive)?[-_ ]?comput|facial[-_ ]?expression|micro[-_ ]?expression",
    r"biometric[-_ ]?categor|\bdeepface\b|fer[-_ ]?2013|ferplus|py[-_ ]?feat|\baffectnet\b",
    r"(emotion|mood|affect)[-_ ]?(from|detect|classif|analy).{0,12}(face|voice|webcam|camera|speech)",
]

# An explicit emotion/biometric exposure notice (Art. 50(3) satisfied).
_EMOTION_NOTICE_PATTERNS = [
    r"(inform|notif|disclos|notice|consent).{0,24}(emotion|biometric)",
    r"(emotion|biometric).{0,24}(inform|notif|disclos|notice|consent)",
    r"you\s+are\s+being\s+(analy[sz]ed|assessed|recorded)",
]

# AI-generated text published on matters of public interest (Art. 50(4), 2nd
# limb). Gated in ``analyze`` on a co-present LLM / generation surface so a
# bare "newsroom" identifier without generation cannot trip it.
_AI_TEXT_PUBLIC_PATTERNS = [
    r"news[-_ ]?(article|story|room|desk|generat)|newsroom|auto[-_ ]?journal|journalism",
    r"press[-_ ]?release",
    r"public[-_ ]?interest[-_ ]?(text|content|article)",
    r"(article|op[-_ ]?ed|editorial)[-_ ]?(generat|writer|bot)",
]

# Upper bound on emitted findings so the analyzer can't flood the violation
# map (it emits at most ~8 in practice: 5 gaps + 3 positives).
_MAX_FINDINGS = 25

_ROLES = [ROLE_PROVIDER, ROLE_DEPLOYER]


def _scan_first(ctx: AnalyzerContext, patterns: list[str]) -> tuple[bool, str, str]:
    """Return (matched?, file_path, matched_line) for the first file+pattern hit."""
    for pattern in patterns:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        for path, content in ctx.files.items():
            match = compiled.search(content)
            if match:
                start = content.rfind("\n", 0, match.start()) + 1
                end = content.find("\n", match.end())
                line = content[start : end if end != -1 else len(content)].strip()
                return True, path, line[:200]
    return False, "", ""


def analyze_article_50_transparency(ctx: AnalyzerContext) -> AnalyzerResult:
    """Detect Art. 50 transparency gaps (chatbot disclosure, synthetic marking,
    emotion/biometric notice, deep-fake / AI-text labelling).

    Detection is aggregate across the repo: a generation, chatbot, or emotion
    surface is a gap only when no disclosure / marking / notice is present
    anywhere. With no relevant surface at all the analyzer returns a neutral
    high score and no findings so a backend-only repo is not falsely flagged.
    """
    findings: list[Finding] = []

    has_chat, chat_file, chat_line = _scan_first(ctx, _CHAT_PATTERNS)
    has_gen, gen_file, gen_line = _scan_first(ctx, _GENERATION_PATTERNS)
    has_deepfake, df_file, df_line = _scan_first(ctx, _DEEPFAKE_PATTERNS)
    has_marking, mark_file, mark_line = _scan_first(ctx, _MARKING_PATTERNS)
    has_disclosure, disc_file, disc_line = _scan_first(ctx, _DISCLOSURE_PATTERNS)
    has_emotion, emo_file, emo_line = _scan_first(ctx, _EMOTION_BIOMETRIC_PATTERNS)
    has_emo_notice, emon_file, emon_line = _scan_first(ctx, _EMOTION_NOTICE_PATTERNS)
    has_ai_text, txt_file, txt_line = _scan_first(ctx, _AI_TEXT_PUBLIC_PATTERNS)

    surface = (
        has_chat or has_gen or has_deepfake or has_marking
        or has_disclosure or has_emotion or has_ai_text
    )
    surface_files: set[str] = {
        f
        for f in (chat_file, gen_file, df_file, mark_file, disc_file, emo_file, txt_file)
        if f
    }

    if not surface:
        # No content-generation / chatbot / emotion surface — Art. 50 does not
        # bite. Neutral high score, no false gaps on a backend-only repo.
        return AnalyzerResult(
            analyzer_id="article_50_transparency",
            label="Art. 50 Transparency",
            findings=[],
            score=80.0,
            file_count=0,
            graph_node_type="control",
            graph_icon="🏷",
            connected_categories=["documentation", "human_oversight"],
        )

    # Art. 50(1) — conversational AI with no AI-interaction disclosure.
    if has_chat and not has_disclosure:
        findings.append(Finding(
            id="art50-no-ai-disclosure",
            category="article_50_transparency",
            title="Conversational AI surface with no Art. 50(1) AI-interaction disclosure",
            description=(
                "A chatbot / assistant surface interacts with natural persons but no "
                "disclosure that they are dealing with an AI system was found. Art. 50(1) "
                "requires the AI-interaction disclosure at first contact (enforceable "
                "2 Aug 2026). Add a clear 'you are interacting with an AI' notice."
            ),
            file_path=chat_file, confidence=0.6,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency", "transparency"],
            evidence_snippet=chat_line,
            kb_question_ids=["tr-1", "ct-6"], suggested_answer="no",
            article_paragraphs=["50(1)"],
            applicable_roles=_ROLES,
        ))

    # Art. 50(2) — synthetic content generated with no machine-readable marking.
    if has_gen and not has_marking:
        findings.append(Finding(
            id="art50-unmarked-synthetic",
            category="article_50_transparency",
            title="Synthetic content generated with no Art. 50(2) machine-readable marking",
            description=(
                "Code generates synthetic image/audio/video/text but no C2PA / watermark "
                "/ provenance marking of the output was found. Art. 50(2) requires "
                "machine-readable marking (the June-2026 Transparency Code of Practice "
                "points at C2PA content credentials). Embed a robust, interoperable mark "
                "on the generated output."
            ),
            file_path=gen_file, confidence=0.6,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=gen_line,
            kb_question_ids=["ct-1", "ct-2"], suggested_answer="no",
            article_paragraphs=["50(2)"],
            applicable_roles=_ROLES,
        ))

    # Art. 50(4) — deep-fake / synthetic media with no disclosure label.
    if has_deepfake and not (has_marking or has_disclosure):
        findings.append(Finding(
            id="art50-unlabelled-deepfake",
            category="article_50_transparency",
            title="Deep-fake / synthetic-media surface with no Art. 50(4) disclosure label",
            description=(
                "A face-swap / voice-clone / synthetic-media surface was found with no "
                "'AI-generated' label or provenance marking. Art. 50(4) requires deep-fake "
                "content to be disclosed as artificially generated or manipulated. Add a "
                "visible label and a machine-readable mark to the output."
            ),
            file_path=df_file, confidence=0.65,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=df_line,
            kb_question_ids=["ct-3"], suggested_answer="no",
            article_paragraphs=["50(4)"],
            applicable_roles=_ROLES,
        ))

    # Art. 50(3) — emotion recognition / biometric categorisation with no
    # exposure notice. A deployer obligation: persons exposed must be informed.
    if has_emotion and not has_emo_notice:
        findings.append(Finding(
            id="art50-emotion-no-notice",
            category="article_50_transparency",
            title="Emotion / biometric-categorisation surface with no Art. 50(3) exposure notice",
            description=(
                "An emotion-recognition or biometric-categorisation surface was found with "
                "no notice informing exposed persons that the system operates on them. "
                "Art. 50(3) requires deployers to inform the natural persons exposed "
                "(enforceable 2 Aug 2026), and the biometric processing must have a GDPR "
                "lawful basis. Add a clear exposure notice at the point of capture."
            ),
            file_path=emo_file, confidence=0.6,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=emo_line,
            kb_question_ids=["ct-5"], suggested_answer="no",
            article_paragraphs=["50(3)"],
            applicable_roles=[ROLE_DEPLOYER],
        ))

    # Art. 50(4), 2nd limb — AI-generated public-interest text with no
    # disclosure. Gated on a co-present LLM / generation surface so a bare
    # "newsroom" identifier without generation cannot trip it.
    if has_ai_text and (has_chat or has_gen) and not (has_marking or has_disclosure):
        findings.append(Finding(
            id="art50-unlabelled-ai-text",
            category="article_50_transparency",
            title="AI-generated public-interest text with no Art. 50(4) disclosure",
            description=(
                "A news / press / public-interest text surface is paired with an LLM or "
                "generation surface but no 'AI-generated' disclosure was found. Art. 50(4) "
                "requires text published to inform the public on matters of public interest "
                "to be disclosed as artificially generated or manipulated, unless it "
                "underwent human review with editorial responsibility. Add the disclosure "
                "or record the editorial-review exception."
            ),
            file_path=txt_file, confidence=0.5,
            compliance_impact="gap",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=txt_line,
            kb_question_ids=["ct-4"], suggested_answer="no",
            article_paragraphs=["50(4)"],
            applicable_roles=[ROLE_DEPLOYER],
        ))

    # Positives — machine-readable marking and/or explicit disclosure present.
    if has_marking:
        findings.append(Finding(
            id="art50-marking-present",
            category="article_50_transparency",
            title="Machine-readable synthetic-content marking present (C2PA / watermark)",
            description=(
                "C2PA / watermark / provenance marking of generated content was found — "
                "the Art. 50(2) machine-readable-marking obligation is being addressed."
            ),
            file_path=mark_file, confidence=0.65,
            compliance_impact="positive",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=mark_line,
            kb_question_ids=["ct-1", "ct-2"], suggested_answer="yes",
            article_paragraphs=["50(2)"],
        ))
    if has_disclosure:
        findings.append(Finding(
            id="art50-disclosure-present",
            category="article_50_transparency",
            title="Explicit AI-interaction / AI-generated disclosure present",
            description=(
                "An explicit AI-interaction or AI-generated disclosure string was found — "
                "the Art. 50(1)/50(4) disclosure obligation is being addressed."
            ),
            file_path=disc_file, confidence=0.6,
            compliance_impact="positive",
            compliance_dimensions=["content_transparency", "transparency"],
            evidence_snippet=disc_line,
            kb_question_ids=["tr-1", "ct-3"], suggested_answer="yes",
            article_paragraphs=["50(1)"],
        ))
    if has_emotion and has_emo_notice:
        findings.append(Finding(
            id="art50-emotion-notice-present",
            category="article_50_transparency",
            title="Emotion / biometric exposure notice present (Art. 50(3))",
            description=(
                "An emotion-recognition / biometric-categorisation exposure notice was "
                "found alongside the analysis surface — the Art. 50(3) obligation to "
                "inform exposed persons is being addressed."
            ),
            file_path=emon_file, confidence=0.6,
            compliance_impact="positive",
            compliance_dimensions=["content_transparency"],
            evidence_snippet=emon_line,
            kb_question_ids=["ct-5"], suggested_answer="yes",
            article_paragraphs=["50(3)"],
        ))

    findings = findings[:_MAX_FINDINGS]

    # Score — gap-only drops hard; positives read well. Mirrors lethal_trifecta.
    gaps = [f for f in findings if f.compliance_impact == "gap"]
    pos = [f for f in findings if f.compliance_impact == "positive"]
    if gaps and not pos:
        score = max(15.0, 50.0 - len(gaps) * 20)
    elif gaps and pos:
        score = max(35.0, 65.0 - len(gaps) * 15 + len(pos) * 5)
    elif pos:
        score = min(95.0, 80.0 + len(pos) * 5)
    else:
        score = 75.0

    score = max(0.0, min(100.0, score))
    return AnalyzerResult(
        analyzer_id="article_50_transparency",
        label="Art. 50 Transparency",
        findings=findings,
        score=round(score, 1),
        file_count=len(surface_files),
        graph_node_type="control",
        graph_icon="🏷",
        connected_categories=["documentation", "human_oversight"],
    )
