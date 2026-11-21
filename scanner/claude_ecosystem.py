"""Offline ingestion for Anthropic Claude Compliance API exports and Claude Code Security reports.

This module is 100% local and offline — it performs ZERO network calls and parses
only local files exported by the user or by ``scripts/fetch_claude_compliance.py``:

1. :func:`ingest_compliance_api_export`:
   Parses local JSON or JSONL snapshots pulled from Anthropic's Claude Compliance
   API (``/v1/compliance/activities``, ``/v1/compliance/groups``,
   ``/v1/compliance/organizations/{org_uuid}/user_preferences``, and
   ``/v1/compliance/apps/sessions/remote/{id}/messages``, header
   ``anthropic-version: 2026-10-21``) and maps organizational governance & audit
   evidence into EU AI Act :class:`scanner.analyzers._base.Finding` objects.

2. :func:`ingest_claude_security_report`:
   Parses local reports emitted by ``claude-security@claude-plugins-official``
   (``/claude-security``) or Claude Code's built-in ``/security-review`` in SARIF
   2.1.0, JSON, or structured Markdown format. Honors Claude Security's
   adversarial verification panel by filtering mitigated, refuted, dismissed, or
   unverified findings and mapping confirmed issues to EU AI Act Art. 15(4) and
   Art. 9(2).
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from scanner.analyzers._base import Finding
from scanner.sarif import ingest_sarif_files

_DEFAULT_API_VERSION = "2026-10-21"
_MIN_RETENTION_DAYS_ART26 = 180

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_URL_RE = re.compile(r"https?://[^\s\"'<>()]+")

# Risky directives in Claude user_preferences ("Instructions for Claude" /
# "Cowork Global instructions") that undermine Art. 14 human oversight,
# Art. 15 security, Art. 12 logging, or Art. 50(1) AI disclosure.
_UNSAFE_PREFERENCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "bypass_security_review",
        re.compile(
            r"\b(?:skip|bypass|ignore|disable|omit|turn\s+off)\s+"
            r"(?:all\s+)?(?:security|safety|compliance|code)\s+"
            r"(?:review|reviews|check|checks|scan|scans|guardrails?|filters?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "hide_ai_disclosure",
        re.compile(
            r"\b(?:never|do\s+not|don't|avoid|refuse\s+to)\s+"
            r"(?:disclose|mention|reveal|tell|admit|indicate|state)\s+"
            r"(?:to\s+(?:users?|customers?|clients?|anyone|them|the\s+public|people|humans?)\s+)?"
            r"(?:that\s+)?"
            r"(?:(?:you\s+are|this\s+is|it\s+is|responses?\s+are|outputs?\s+are|"
            r"answers?\s+are|messages?\s+are|content\s+is|they\s+are)\s+)?"
            r"(?:an?\s+)?(?:ai[- ]generated|ai\b|artificial\s+intelligence|claude|automated|bot)\b"
            r"|\b(?:hide|conceal|strip|remove)\s+(?:all\s+)?(?:ai\s+disclosure|"
            r"ai\s+watermarks?|ai\s+labels?|c2pa|provenance)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_human_approval",
        re.compile(
            r"\b(?:bypass|skip|ignore|disable|auto[- ]?approve)\s+"
            r"(?:all\s+)?(?:human\s+)?(?:approval|approvals|oversight|"
            r"confirmation|confirmations|sign[- ]?off|permission\s+prompts?)\b"
            r"|\bnever\s+ask\s+(?:for\s+)?(?:human\s+)?(?:confirmation|approval|permission)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "disable_audit_logging",
        re.compile(
            r"\b(?:disable|turn\s+off|suppress|skip|bypass|avoid)\s+"
            r"(?:all\s+)?(?:audit\s+)?(?:logging|logs|audit\s+trails?|recording|telemetry)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ignore_pii_gdpr",
        re.compile(
            r"\b(?:ignore|bypass|skip|disregard|disable)\s+"
            r"(?:all\s+)?(?:pii|gdpr|privacy|data\s+protection|redaction|confidentiality)\b",
            re.IGNORECASE,
        ),
    ),
)

# High-risk remote session tool / action keywords (Art. 14(4) human oversight).
_HIGH_RISK_ACTION_RE = re.compile(
    r"\b(?:bash|shell|sh|exec|execute_command|run_command|terminal|"
    r"delete|rm\b|rmdir|remove_file|destroy|purge|wipe|"
    r"deploy|release|publish|terraform_apply|kubectl_apply|prod_deploy|"
    r"db[-_ ]?drop|drop[-_ ]?table|drop[-_ ]?database|truncate[-_ ]?table|"
    r"sql_write|destructive_migration|sudo|chmod)\b",
    re.IGNORECASE,
)

_UNAPPROVED_STATUSES = frozenset(
    {"unapproved", "denied", "rejected", "skipped", "bypassed", "none", "unreviewed"}
)

_ADVERSARIAL_REJECTED_STATUSES = frozenset(
    {
        "mitigated",
        "false_positive",
        "false-positive",
        "false positive",
        "dismissed",
        "refuted",
        "rejected",
        "unverified",
        "suppressed",
        "wont_fix",
        "won't fix",
    }
)

_SEVERITY_CONFIDENCE: dict[str, float] = {
    "critical": 0.95,
    "high": 0.90,
    "error": 0.90,
    "medium": 0.75,
    "moderate": 0.75,
    "warning": 0.75,
    "low": 0.60,
    "info": 0.50,
    "informational": 0.50,
}

# Markdown parsing helpers for /claude-security and /security-review reports.
_MD_HEADING_RE = re.compile(r"^(#{2,4})\s+(.+?)\s*$")
_MD_BADGE_RE = re.compile(
    r"\[(?:(CRITICAL|HIGH|MEDIUM|MODERATE|LOW|INFO|MITIGATED|FALSE\s+POSITIVE|DISMISSED|REFUTED))\]",
    re.IGNORECASE,
)
_MD_SEVERITY_LINE_RE = re.compile(
    r"(?:^|\*\*|\b)severity\s*\*?\*?\s*:\s*\*?\*?\s*(critical|high|medium|moderate|low|info)\b",
    re.IGNORECASE,
)
_MD_STATUS_LINE_RE = re.compile(
    r"(?:^|\*\*|\b)(?:status|verdict|verification|adversarial\s+panel)\s*\*?\*?\s*:\s*\*?\*?\s*"
    r"(mitigated|false[- ]positive|dismissed|refuted|rejected|unverified|confirmed|verified|open)\b",
    re.IGNORECASE,
)
_MD_BOOL_FALSE_RE = re.compile(
    r"(?:^|\*\*|\b)(?:verified|confirmed)\s*\*?\*?\s*:\s*\*?\*?\s*(?:false|no)\b",
    re.IGNORECASE,
)
_MD_FILE_LINE_RE = re.compile(
    r"(?:`|\b)([A-Za-z0-9_.\-/\\]+\.[A-Za-z0-9]{1,10}):(\d+)(?:`|\b)"
)
_MD_FILE_ONLY_RE = re.compile(
    r"(?:^|\*\*|\b)(?:file|location|path)\s*\*?\*?\s*:\s*`?([A-Za-z0-9_.\-/\\]+\.[A-Za-z0-9]{1,10})`?",
    re.IGNORECASE,
)
_MD_REMEDIATION_RE = re.compile(
    r"(?:^|\*\*|\b)(?:remediation|fix|patch|recommendation)\s*\*?\*?\s*:\s*(.+)",
    re.IGNORECASE,
)


def _slugify(value: str, *, max_len: int = 48) -> str:
    slug = _SLUG_RE.sub("-", value.lower()).strip("-")
    if not slug:
        return "item"
    return slug[:max_len].rstrip("-") or "item"


def _strip_urls(text: str) -> str:
    """Redact embedded http(s) URLs so offline Finding payloads stay strictly URL-free."""
    if not text:
        return ""
    return _URL_RE.sub("[redacted-url]", text)


def _norm_path(path: str | Path) -> str:
    cleaned = str(path).strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _parse_int_line(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 1:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        return parsed if parsed >= 1 else None
    return None


def _build_finding(
    *,
    finding_id: str,
    category: str,
    title: str,
    description: str,
    file_path: str,
    confidence: float,
    compliance_impact: str,
    compliance_dimensions: list[str],
    evidence_snippet: str,
    article_paragraphs: list[str],
    severity: str | None = None,
    line_number: int | None = None,
) -> Finding:
    """Construct a Finding compatible with current and extended Finding schemas."""
    kwargs: dict[str, Any] = {
        "id": finding_id,
        "category": category,
        "title": _strip_urls(title),
        "description": _strip_urls(description),
        "file_path": _strip_urls(_norm_path(file_path)),
        "confidence": max(0.0, min(1.0, float(confidence))),
        "compliance_impact": compliance_impact,
        "compliance_dimensions": list(compliance_dimensions),
        "evidence_snippet": _strip_urls(evidence_snippet)[:200],
        "article_paragraphs": list(article_paragraphs),
    }
    if severity is not None and "severity" in Finding.model_fields:
        kwargs["severity"] = severity
    if line_number is not None and "line_number" in Finding.model_fields:
        kwargs["line_number"] = line_number
    return Finding(**kwargs)


# ---------------------------------------------------------------------------
# 1. Anthropic Claude Compliance API offline export ingestion
# ---------------------------------------------------------------------------


def _infer_compliance_resource_from_endpoint(endpoint: str) -> str | None:
    low = endpoint.lower()
    if "activit" in low:
        return "activities"
    if "group" in low:
        return "groups"
    if "user_preference" in low or "preference" in low:
        return "user_preferences"
    if "remote" in low or "session" in low or "message" in low:
        return "remote_sessions"
    return None


def _infer_compliance_resource_from_item(item: dict[str, Any]) -> str:
    explicit = item.get("endpoint") or item.get("resource_type") or item.get("resource")
    if isinstance(explicit, str):
        inferred = _infer_compliance_resource_from_endpoint(explicit)
        if inferred:
            return inferred

    keys = {k.lower() for k in item.keys()}

    if keys & {
        "instructions",
        "global_instructions",
        "cowork_instructions",
        "cowork_global_instructions",
        "user_instructions",
        "custom_instructions",
        "preferences",
    }:
        return "user_preferences"

    if keys & {
        "session_id",
        "remote_session_id",
        "messages",
        "tool_name",
        "tool_calls",
        "tool_use",
        "bypass_permissions",
        "approved",
        "human_approved",
    }:
        return "remote_sessions"

    if keys & {"group_id", "member_count", "members", "group_name"}:
        return "groups"

    if keys & {
        "event_type",
        "activity_type",
        "action",
        "actor",
        "actor_id",
        "event_id",
        "audit_event",
    }:
        return "activities"

    # Raw /v1/compliance/groups records are just {id, name, created_at, ...}:
    # no actor and no event type. Without this they fell through to the
    # "activities" default and were counted as audit-trail evidence.
    if "role" in keys or "roles" in keys or ("name" in keys and "type" not in keys):
        return "groups"

    return "activities"


def _extract_retention_days(obj: dict[str, Any]) -> int | None:
    for key in ("retention_days", "log_retention_days", "audit_retention_days"):
        val = obj.get(key)
        if isinstance(val, bool):
            continue
        if isinstance(val, (int, float)) and val >= 0:
            return int(val)
    meta = obj.get("metadata")
    if isinstance(meta, dict):
        for key in ("retention_days", "log_retention_days", "audit_retention_days"):
            val = meta.get(key)
            if not isinstance(val, bool) and isinstance(val, (int, float)) and val >= 0:
                return int(val)
    return None


def _collect_instruction_strings(pref: Any) -> list[str]:
    """Extract all free-text instruction values from a user_preferences record."""
    texts: list[str] = []
    if isinstance(pref, str):
        if pref.strip():
            texts.append(pref.strip())
        return texts
    if not isinstance(pref, dict):
        return texts

    for key in (
        "instructions",
        "global_instructions",
        "cowork_instructions",
        "cowork_global_instructions",
        "user_instructions",
        "custom_instructions",
        "system_prompt",
        "prompt",
        "content",
        "text",
        "value",
    ):
        val = pref.get(key)
        if isinstance(val, str) and val.strip():
            texts.append(val.strip())
        elif isinstance(val, list):
            for sub in val:
                texts.extend(_collect_instruction_strings(sub))
        elif isinstance(val, dict):
            texts.extend(_collect_instruction_strings(val))

    for nested_key in ("preferences", "settings", "profile"):
        nested = pref.get(nested_key)
        if isinstance(nested, dict):
            texts.extend(_collect_instruction_strings(nested))
        elif isinstance(nested, list):
            for sub in nested:
                texts.extend(_collect_instruction_strings(sub))

    return texts


def _iter_remote_session_events(remote_sessions: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """Flatten remote session envelopes and message/tool_call objects into (session_id, event)."""
    events: list[tuple[str, dict[str, Any]]] = []
    for idx, entry in enumerate(remote_sessions):
        session_id = str(
            entry.get("session_id")
            or entry.get("remote_session_id")
            or entry.get("id")
            or f"session-{idx + 1}"
        )
        nested_messages = entry.get("messages") or entry.get("events")
        if isinstance(nested_messages, list):
            for msg in nested_messages:
                if not isinstance(msg, dict):
                    continue
                events.append((session_id, msg))
                tool_calls = msg.get("tool_calls") or msg.get("tool_use")
                if isinstance(tool_calls, list):
                    for tc in tool_calls:
                        if isinstance(tc, dict):
                            merged = dict(msg)
                            merged.update(tc)
                            events.append((session_id, merged))
        else:
            events.append((session_id, entry))
    return events


def _is_unreviewed_high_risk_action(event: dict[str, Any]) -> tuple[bool, str]:
    """Return (is_flagged, action_label) if a remote session event is an unreviewed risky tool action."""
    bypass = (
        event.get("bypass_permissions") is True
        or str(event.get("permission_mode", "")).strip().lower() == "bypasspermissions"
    )
    approved_false = (
        event.get("approved") is False
        or event.get("human_approved") is False
        or str(event.get("approval_status", "")).strip().lower() in _UNAPPROVED_STATUSES
    )
    if not (bypass or approved_false):
        return False, ""

    candidates = [
        str(event.get("tool_name") or ""),
        str(event.get("tool") or ""),
        str(event.get("action") or ""),
        str(event.get("command") or ""),
        str(event.get("name") or ""),
    ]
    tool_input = event.get("input") or event.get("arguments") or event.get("params")
    if isinstance(tool_input, dict):
        candidates.append(json.dumps(tool_input, sort_keys=True))
    elif isinstance(tool_input, str):
        candidates.append(tool_input)

    content = event.get("content")
    if isinstance(content, str):
        candidates.append(content)

    haystack = " ".join(c for c in candidates if c)
    match = _HIGH_RISK_ACTION_RE.search(haystack)
    if not match:
        return False, ""

    label = (
        str(event.get("tool_name") or event.get("tool") or event.get("action") or match.group(0))
        .strip()
    )
    return True, label


def _load_compliance_file(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse a local JSON or JSONL compliance export file.

    Returns ``(classified_buckets_list, metadata_hints)`` or raises ``ValueError``.
    """
    if not path.is_file():
        raise ValueError(f"Compliance API export file not found: {path}")

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Failed to read compliance API export {path}: {exc}") from exc

    stripped = raw_text.strip()
    if not stripped:
        raise ValueError(f"Empty compliance API export file: {path}")

    parsed: Any = None
    json_error: json.JSONDecodeError | None = None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        json_error = exc

    if parsed is None:
        # Try JSONL (one JSON object per non-empty line)
        records: list[dict[str, Any]] = []
        for lineno, line in enumerate(stripped.splitlines(), start=1):
            line_s = line.strip()
            if not line_s:
                continue
            try:
                rec = json.loads(line_s)
            except json.JSONDecodeError as exc:
                msg = json_error.msg if json_error else exc.msg
                raise ValueError(
                    f"Malformed JSON/JSONL in compliance API export {path} (line {lineno}): {msg}"
                ) from exc
            if not isinstance(rec, dict):
                raise ValueError(
                    f"Invalid JSONL record in compliance API export {path} (line {lineno}): expected object"
                )
            records.append(rec)
        return records, {"format": "jsonl"}

    if isinstance(parsed, list):
        records = [item for item in parsed if isinstance(item, dict)]
        if len(records) != len(parsed):
            raise ValueError(
                f"Invalid array items in compliance API export {path}: expected JSON objects"
            )
        return records, {"format": "json_array"}

    if not isinstance(parsed, dict):
        raise ValueError(
            f"Invalid JSON structure in compliance API export {path}: expected object or array"
        )

    return [parsed], {"format": "json_object", "envelope": parsed}


def ingest_compliance_api_export(
    paths: Sequence[str | Path],
) -> tuple[list[Finding], dict[str, Any]]:
    """Parse one or more local Anthropic Claude Compliance API export files into Findings.

    Supports:
    - Combined snapshot dict (``activities``, ``groups``, ``user_preferences``,
      ``remote_sessions``, ``retention_days``)
    - Raw Anthropic paginated payload (``{"data": [...], "has_more": ..., "endpoint": "..."}``)
    - JSONL (one event object per line)

    Raises:
        ValueError: if a file is missing, unreadable, empty, or malformed JSON/JSONL.
    """
    if not paths:
        return [], {
            "source": "anthropic_claude_compliance_api",
            "api_version": _DEFAULT_API_VERSION,
            "files_ingested": [],
            "counts": {
                "activities": 0,
                "groups": 0,
                "user_preferences": 0,
                "remote_sessions": 0,
                "remote_messages": 0,
            },
            "retention_days": None,
            "unsafe_preferences_count": 0,
            "unreviewed_remote_actions_count": 0,
            "findings_emitted": 0,
        }

    activities: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    user_preferences: list[dict[str, Any]] = []
    remote_sessions: list[dict[str, Any]] = []

    retention_days: int | None = None
    api_version: str = _DEFAULT_API_VERSION
    files_ingested: list[str] = []
    # True once any input actually covers the activities resource. An export of
    # only groups / user_preferences says nothing about the audit trail, so it
    # must not raise the "empty activity trail" gap.
    activities_exported = False

    buckets: dict[str, list[dict[str, Any]]] = {
        "activities": activities,
        "groups": groups,
        "user_preferences": user_preferences,
        "remote_sessions": remote_sessions,
    }

    for raw_path in paths:
        path = Path(raw_path)
        norm = _norm_path(path)
        records, hints = _load_compliance_file(path)
        files_ingested.append(norm)

        if hints.get("format") == "json_object":
            envelope: dict[str, Any] = hints["envelope"]
            if isinstance(envelope.get("api_version"), str) and envelope["api_version"].strip():
                api_version = envelope["api_version"].strip()

            ret = _extract_retention_days(envelope)
            if ret is not None:
                retention_days = ret if retention_days is None else min(retention_days, ret)

            # Combined snapshot dict
            is_combined = any(
                k in envelope
                for k in ("activities", "groups", "user_preferences", "remote_sessions")
            )
            if is_combined:
                if "activities" in envelope:
                    activities_exported = True
                for key in ("activities", "groups", "user_preferences", "remote_sessions"):
                    val = envelope.get(key)
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, dict):
                                buckets[key].append(item)
                    elif isinstance(val, dict):
                        buckets[key].append(val)
                continue

            # Raw Anthropic paginated payload: {"data": [...], "has_more": ..., "endpoint": "..."}
            if isinstance(envelope.get("data"), list):
                endpoint = str(envelope.get("endpoint") or envelope.get("resource") or "")
                inferred_bucket = _infer_compliance_resource_from_endpoint(endpoint) if endpoint else None
                if inferred_bucket == "activities":
                    activities_exported = True
                for item in envelope["data"]:
                    if not isinstance(item, dict):
                        continue
                    item_ret = _extract_retention_days(item)
                    if item_ret is not None:
                        retention_days = item_ret if retention_days is None else min(retention_days, item_ret)
                    target = inferred_bucket or _infer_compliance_resource_from_item(item)
                    if target == "activities":
                        activities_exported = True
                    buckets[target].append(item)
                continue

            # Single-record object fallback
            target = _infer_compliance_resource_from_item(envelope)
            if target == "activities":
                activities_exported = True
            buckets[target].append(envelope)
        else:
            # JSONL or JSON array
            for rec in records:
                item_ret = _extract_retention_days(rec)
                if item_ret is not None:
                    retention_days = item_ret if retention_days is None else min(retention_days, item_ret)
                target = _infer_compliance_resource_from_item(rec)
                if target == "activities":
                    activities_exported = True
                buckets[target].append(rec)

    primary_file = files_ingested[0]
    findings: list[Finding] = []

    # 1. Activity audit trail & Art. 26(6) retention check
    if activities:
        ret_note = f"{retention_days} days" if retention_days is not None else "unspecified"
        findings.append(
            _build_finding(
                finding_id="cca-activity-audit-trail",
                category="claude_compliance_api",
                title=f"Claude Compliance API audit trail verified ({len(activities)} activity events)",
                description=(
                    f"Local Claude Compliance API export ({primary_file}) contains {len(activities)} "
                    f"organization activity events (configured retention: {ret_note}), supporting "
                    f"EU AI Act Art. 12(1) record-keeping and Art. 26(6) deployer log retention."
                ),
                file_path=primary_file,
                confidence=0.90,
                compliance_impact="positive",
                compliance_dimensions=["logging", "deployer_obligations"],
                evidence_snippet=f"activities={len(activities)}; retention_days={ret_note}; api_version={api_version}",
                article_paragraphs=["Art. 12(1)", "Art. 26(6)"],
                severity="info",
            )
        )

    short_retention = retention_days is not None and retention_days < _MIN_RETENTION_DAYS_ART26
    empty_trail = activities_exported and len(activities) == 0
    if short_retention or empty_trail:
        if short_retention:
            reason = (
                f"Configured log retention is {retention_days} days, which is below the "
                f"EU AI Act Art. 26(6) 6-month ({_MIN_RETENTION_DAYS_ART26}-day) deployer minimum."
            )
            snippet = f"retention_days={retention_days} < {_MIN_RETENTION_DAYS_ART26}; activities={len(activities)}"
        else:
            reason = (
                "Compliance API export contains 0 activity events, so EU AI Act Art. 26(6) "
                "deployer audit log retention (>=6 months) cannot be verified."
            )
            snippet = f"activities=0; retention_days={retention_days}"
        findings.append(
            _build_finding(
                finding_id="cca-short-log-retention",
                category="claude_compliance_api",
                title="Insufficient Claude Compliance API audit log retention or empty activity trail",
                description=(
                    f"{reason} Export periodic snapshots from /v1/compliance/activities and "
                    f"archive them locally or in immutable WORM storage for at least 6 months."
                ),
                file_path=primary_file,
                confidence=0.90,
                compliance_impact="gap",
                compliance_dimensions=["logging", "deployer_obligations"],
                evidence_snippet=snippet,
                article_paragraphs=["Art. 26(6)", "Art. 12(1)"],
                severity="high",
            )
        )

    # 2. Organization group governance (Art. 26(2))
    if groups:
        group_names = [
            str(g.get("name") or g.get("group_name") or g.get("id") or g.get("group_id") or "group")
            for g in groups[:5]
        ]
        findings.append(
            _build_finding(
                finding_id="cca-org-group-governance",
                category="claude_compliance_api",
                title=f"Claude organization group governance verified ({len(groups)} groups)",
                description=(
                    f"Compliance export documents {len(groups)} organization group(s) "
                    f"({', '.join(group_names)}), evidencing role-based assignment of human oversight "
                    f"and access boundaries under EU AI Act Art. 26(2)."
                ),
                file_path=primary_file,
                confidence=0.85,
                compliance_impact="positive",
                compliance_dimensions=["quality_management", "access_control"],
                evidence_snippet=f"groups={len(groups)}; sample={', '.join(group_names)}",
                article_paragraphs=["Art. 26(2)"],
                severity="info",
            )
        )

    # 3. User preferences ("Instructions for Claude" / "Cowork Global instructions")
    unsafe_pref_matches: list[tuple[str, str]] = []
    for idx, pref in enumerate(user_preferences):
        pref_id = str(
            pref.get("user_id")
            or pref.get("user_uuid")
            or pref.get("id")
            or f"user-{idx + 1}"
        )
        texts = _collect_instruction_strings(pref)
        combined_text = "\n".join(texts)
        for rule_name, pattern in _UNSAFE_PREFERENCE_PATTERNS:
            if pattern.search(combined_text):
                unsafe_pref_matches.append((pref_id, rule_name))

    if unsafe_pref_matches:
        unique_rules = sorted({rule for _, rule in unsafe_pref_matches})
        sample_users = sorted({uid for uid, _ in unsafe_pref_matches})[:5]
        findings.append(
            _build_finding(
                finding_id="cca-unsafe-user-preferences",
                category="claude_compliance_api",
                title=(
                    f"Unsafe bypass directives in Claude user preferences "
                    f"({len(unsafe_pref_matches)} match(es))"
                ),
                description=(
                    f"User preference instructions (Instructions for Claude / Cowork Global "
                    f"instructions) contain risky bypass directives ({', '.join(unique_rules)}) "
                    f"across {len(sample_users)} profile(s) ({', '.join(sample_users)}). "
                    f"Remove instructions that skip security reviews, disable logging, bypass "
                    f"human approval (Art. 14(1)), or suppress AI disclosure (Art. 50(1))."
                ),
                file_path=primary_file,
                confidence=0.90,
                compliance_impact="gap",
                compliance_dimensions=["security", "human_oversight", "content_transparency"],
                evidence_snippet=(
                    f"matches={len(unsafe_pref_matches)}; rules={','.join(unique_rules)}; "
                    f"profiles={','.join(sample_users)}"
                ),
                article_paragraphs=["Art. 14(1)", "Art. 50(1)"],
                severity="high",
            )
        )
    elif user_preferences:
        findings.append(
            _build_finding(
                finding_id="cca-user-preferences-audited",
                category="claude_compliance_api",
                title=f"Claude user preferences audited ({len(user_preferences)} profile(s) clean)",
                description=(
                    f"Audited {len(user_preferences)} Claude user_preferences profile(s) "
                    f"with zero security-bypass, oversight-bypass, or AI-disclosure suppression "
                    f"directives detected (Art. 14(1), Art. 50(1))."
                ),
                file_path=primary_file,
                confidence=0.80,
                compliance_impact="positive",
                compliance_dimensions=["security", "human_oversight", "content_transparency"],
                evidence_snippet=f"user_preferences={len(user_preferences)}; unsafe_matches=0",
                article_paragraphs=["Art. 14(1)", "Art. 50(1)"],
                severity="info",
            )
        )

    # 4. Remote session tool execution oversight (Art. 14(4))
    session_events = _iter_remote_session_events(remote_sessions)
    unreviewed_actions: list[tuple[str, str]] = []
    seen_action_keys: set[tuple[str, str]] = set()
    for session_id, ev in session_events:
        flagged, action_label = _is_unreviewed_high_risk_action(ev)
        if flagged:
            action_key = (session_id, action_label)
            if action_key not in seen_action_keys:
                seen_action_keys.add(action_key)
                unreviewed_actions.append(action_key)

    if unreviewed_actions:
        sample_actions = [f"{sid}:{act}" for sid, act in unreviewed_actions[:5]]
        findings.append(
            _build_finding(
                finding_id="cca-unreviewed-remote-session-actions",
                category="claude_compliance_api",
                title=(
                    f"Unreviewed high-risk tool executions in remote Claude sessions "
                    f"({len(unreviewed_actions)} action(s))"
                ),
                description=(
                    f"Remote session logs recorded {len(unreviewed_actions)} high-risk tool "
                    f"execution(s) marked unapproved or with bypass_permissions enabled "
                    f"({', '.join(sample_actions)}). Enforce explicit human approval gates "
                    f"and remove bypass_permissions on destructive/deployment tools (Art. 14(4))."
                ),
                file_path=primary_file,
                confidence=0.90,
                compliance_impact="gap",
                compliance_dimensions=["tool_governance", "human_oversight"],
                evidence_snippet=f"unreviewed_actions={len(unreviewed_actions)}; sample={','.join(sample_actions)}",
                article_paragraphs=["Art. 14(4)"],
                severity="high",
            )
        )
    elif remote_sessions:
        findings.append(
            _build_finding(
                finding_id="cca-remote-sessions-monitored",
                category="claude_compliance_api",
                title=f"Remote Claude sessions monitored ({len(remote_sessions)} session record(s) clean)",
                description=(
                    f"Audited {len(remote_sessions)} remote session record(s) ({len(session_events)} "
                    f"event(s)) with no unapproved high-risk tool executions or permission-bypass "
                    f"flags detected (Art. 14(4))."
                ),
                file_path=primary_file,
                confidence=0.80,
                compliance_impact="positive",
                compliance_dimensions=["tool_governance", "human_oversight"],
                evidence_snippet=f"remote_sessions={len(remote_sessions)}; events={len(session_events)}; unreviewed=0",
                article_paragraphs=["Art. 14(4)"],
                severity="info",
            )
        )

    metadata: dict[str, Any] = {
        "source": "anthropic_claude_compliance_api",
        "api_version": api_version,
        "files_ingested": files_ingested,
        "counts": {
            "activities": len(activities),
            "groups": len(groups),
            "user_preferences": len(user_preferences),
            "remote_sessions": len(remote_sessions),
            "remote_messages": len(session_events),
        },
        "retention_days": retention_days,
        "unsafe_preferences_count": len(unsafe_pref_matches),
        "unreviewed_remote_actions_count": len(unreviewed_actions),
        "findings_emitted": len(findings),
    }
    return findings, metadata


# ---------------------------------------------------------------------------
# 2. Claude Code Security (/claude-security & /security-review) report ingestion
# ---------------------------------------------------------------------------


def _is_filtered_by_adversarial_panel(item: dict[str, Any]) -> bool:
    """True when Claude Security's adversarial verification panel refuted/mitigated the item."""
    if item.get("verified") is False:
        return True
    if item.get("confirmed") is False:
        return True
    if item.get("mitigated") is True:
        return True
    if item.get("false_positive") is True:
        return True

    for key in ("status", "verification_status", "verdict", "panel_verdict", "disposition"):
        val = item.get(key)
        if isinstance(val, str) and val.strip().lower() in _ADVERSARIAL_REJECTED_STATUSES:
            return True

    panel = item.get("adversarial_panel") or item.get("verification")
    if isinstance(panel, dict):
        if panel.get("verified") is False or panel.get("confirmed") is False:
            return True
        verdict = str(panel.get("verdict") or panel.get("status") or "").strip().lower()
        if verdict in _ADVERSARIAL_REJECTED_STATUSES:
            return True

    return False


def _normalize_severity(raw: Any) -> str:
    low = str(raw or "medium").strip().lower()
    if low in {"critical", "crit", "p0"}:
        return "critical"
    if low in {"high", "error", "p1"}:
        return "high"
    if low in {"medium", "moderate", "warning", "warn", "p2"}:
        return "medium"
    if low in {"low", "minor", "p3", "info", "informational", "note", "p4"}:
        return "low"
    return "medium"


def _parse_jsonl_findings(text: str) -> list[dict[str, Any]] | None:
    """Parse JSON Lines (one finding object per line); None if any line is not an object."""
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        try:
            rec = json.loads(line_s)
        except json.JSONDecodeError:
            return None
        if not isinstance(rec, dict):
            return None
        records.append(rec)
    return records or None


def _split_file_and_line(raw_file: str, explicit_line: int | None) -> tuple[str, int | None]:
    cleaned = _norm_path(raw_file)
    if explicit_line is not None:
        return cleaned, explicit_line
    match = re.match(r"^(.+):(\d+)$", cleaned)
    if match:
        return match.group(1), int(match.group(2))
    return cleaned, None


def _ingest_claude_security_json(
    data: Any,
    path: Path,
    counter_start: int,
) -> tuple[list[Finding], int, int, dict[str, int]]:
    """Parse JSON findings from /claude-security or /security-review."""
    raw_items: list[Any] | None = None
    if isinstance(data, list):
        raw_items = data
    elif isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            if isinstance(data.get(key), list):
                raw_items = data[key]
                break
        if raw_items is None and (data.get("file") or data.get("file_path")) and (
            data.get("severity") or data.get("title") or data.get("description")
        ):
            raw_items = [data]  # a single bare finding object
    if raw_items is None:
        raise ValueError(
            f"Invalid Claude Security JSON report in {path}: expected top-level array or "
            f"object containing a 'findings' list"
        )

    findings: list[Finding] = []
    filtered_count = 0
    total_raw = 0
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    counter = counter_start

    for item in raw_items:
        if not isinstance(item, dict):
            continue
        total_raw += 1

        if _is_filtered_by_adversarial_panel(item):
            filtered_count += 1
            continue

        severity = _normalize_severity(item.get("severity") or item.get("level"))
        confidence = _SEVERITY_CONFIDENCE.get(severity, 0.75)

        raw_file = str(
            item.get("file_path")
            or item.get("file")
            or item.get("path")
            or item.get("location")
            or ""
        ).strip()
        raw_line = (
            _parse_int_line(item.get("line_number"))
            or _parse_int_line(item.get("line"))
            or _parse_int_line(item.get("start_line"))
        )
        file_path, line_number = _split_file_and_line(raw_file, raw_line)

        raw_id = str(item.get("id") or item.get("rule_id") or "").strip()
        desc = str(item.get("description") or item.get("details") or item.get("message") or "").strip()
        # anthropics/claude-code-security-review findings carry no title: they
        # are keyed by `category` (e.g. "sql_injection") plus a description.
        category = str(item.get("category") or "").strip().replace("_", " ")
        first_sentence = desc.split(". ")[0].strip().rstrip(".")[:90] if desc else ""
        title = str(
            item.get("title")
            or item.get("name")
            or item.get("summary")
            or (f"{category}: {first_sentence}" if category and first_sentence else category)
            or first_sentence
            or raw_id
            or "Security finding"
        ).strip()
        if not desc:
            desc = title
        exploit = str(item.get("exploit_scenario") or "").strip()
        if exploit:
            desc = f"{desc} Exploit scenario: {exploit}"
        remediation = str(
            item.get("remediation") or item.get("patch") or item.get("fix") or item.get("recommendation") or ""
        ).strip()

        counter += 1
        id_slug = _slugify(raw_id or title, max_len=36)
        finding_id = f"claude-sec-{id_slug}-{counter}"

        loc_label = f"{file_path}:{line_number}" if (file_path and line_number) else (file_path or "repository")
        full_desc = (
            f"Claude Code Security confirmed finding (severity={severity}, location={loc_label}): {desc}"
        )
        if remediation:
            full_desc += f" Remediation: {remediation}"

        evidence = f"severity={severity}; location={loc_label}"
        if remediation:
            evidence += f"; fix={remediation}"

        sev_counts[severity] = sev_counts.get(severity, 0) + 1
        findings.append(
            _build_finding(
                finding_id=finding_id,
                category="claude_security_plugin",
                title=f"[claude-security] {title}",
                description=full_desc,
                file_path=file_path or _norm_path(path),
                confidence=confidence,
                compliance_impact="gap",
                compliance_dimensions=["security", "access_control", "risk_mgmt"],
                evidence_snippet=evidence,
                article_paragraphs=["Art. 15(4)", "Art. 9(2)"],
                severity=severity,
                line_number=line_number,
            )
        )

    return findings, total_raw, filtered_count, sev_counts


def _ingest_claude_security_markdown(
    text: str,
    path: Path,
    counter_start: int,
) -> tuple[list[Finding], int, int, dict[str, int]]:
    """Parse structured Markdown findings emitted by /claude-security or /security-review."""
    lines = text.splitlines()
    sections: list[tuple[str, list[str]]] = []
    current_heading: str | None = None
    current_body: list[str] = []

    for line in lines:
        m = _MD_HEADING_RE.match(line)
        if m:
            if current_heading is not None:
                sections.append((current_heading, current_body))
            current_heading = m.group(2).strip()
            current_body = []
        elif current_heading is not None:
            current_body.append(line)
    if current_heading is not None:
        sections.append((current_heading, current_body))

    findings: list[Finding] = []
    total_raw = 0
    filtered_count = 0
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    counter = counter_start

    for heading, body_lines in sections:
        body = "\n".join(body_lines).strip()
        heading_badges = [b.upper() for b in _MD_BADGE_RE.findall(heading)]
        sev_line_match = _MD_SEVERITY_LINE_RE.search(body)

        # Only treat a heading as a finding section if it carries a severity badge,
        # an adversarial-panel status badge, or an explicit Severity: field.
        if not heading_badges and not sev_line_match:
            continue

        total_raw += 1

        # Check adversarial verification panel status in heading badges or body
        rejected_badge = any(
            b.lower() in _ADVERSARIAL_REJECTED_STATUSES for b in heading_badges
        )
        status_match = _MD_STATUS_LINE_RE.search(body)
        rejected_status = bool(
            status_match and status_match.group(1).strip().lower() in _ADVERSARIAL_REJECTED_STATUSES
        )
        rejected_bool = bool(_MD_BOOL_FALSE_RE.search(body))

        if rejected_badge or rejected_status or rejected_bool:
            filtered_count += 1
            continue

        raw_sev = "medium"
        for badge in heading_badges:
            if badge.lower() in {"critical", "high", "medium", "moderate", "low", "info"}:
                raw_sev = badge.lower()
                break
        if sev_line_match:
            raw_sev = sev_line_match.group(1).lower()
        severity = _normalize_severity(raw_sev)
        confidence = _SEVERITY_CONFIDENCE.get(severity, 0.75)

        clean_title = _MD_BADGE_RE.sub("", heading).strip(" -:\t") or heading
        file_path = ""
        line_number: int | None = None

        file_line_match = _MD_FILE_LINE_RE.search(f"{heading}\n{body}")
        if file_line_match:
            file_path = _norm_path(file_line_match.group(1))
            line_number = int(file_line_match.group(2))
        else:
            file_only_match = _MD_FILE_ONLY_RE.search(body)
            if file_only_match:
                file_path = _norm_path(file_only_match.group(1))

        remediation_match = _MD_REMEDIATION_RE.search(body)
        remediation = remediation_match.group(1).strip() if remediation_match else ""

        # Compact body summary for description
        body_summary = " ".join(
            ln.strip() for ln in body_lines if ln.strip() and not ln.strip().startswith("```")
        )[:400]

        counter += 1
        finding_id = f"claude-sec-{_slugify(clean_title, max_len=36)}-{counter}"
        loc_label = f"{file_path}:{line_number}" if (file_path and line_number) else (file_path or "repository")

        desc = f"Claude Code Security confirmed finding (severity={severity}, location={loc_label}): {body_summary or clean_title}"
        if remediation and remediation not in desc:
            desc += f" Remediation: {remediation}"

        evidence = f"severity={severity}; location={loc_label}"
        if remediation:
            evidence += f"; fix={remediation}"

        sev_counts[severity] = sev_counts.get(severity, 0) + 1
        findings.append(
            _build_finding(
                finding_id=finding_id,
                category="claude_security_plugin",
                title=f"[claude-security] {clean_title}",
                description=desc,
                file_path=file_path or _norm_path(path),
                confidence=confidence,
                compliance_impact="gap",
                compliance_dimensions=["security", "access_control", "risk_mgmt"],
                evidence_snippet=evidence,
                article_paragraphs=["Art. 15(4)", "Art. 9(2)"],
                severity=severity,
                line_number=line_number,
            )
        )

    return findings, total_raw, filtered_count, sev_counts


def ingest_claude_security_report(
    paths: Sequence[str | Path],
) -> tuple[list[Finding], dict[str, Any]]:
    """Ingest local findings reports from ``claude-security@claude-plugins-official`` or ``/security-review``.

    Supports:
    - SARIF 2.1.0 files (detected via ``"version": "2.1.0"`` + ``"runs"`` and
      delegated to :func:`scanner.sarif.ingest_sarif_files`)
    - JSON reports (``{"findings": [...]}`` or ``[...]``)
    - Structured Markdown reports (finding sections with ``[CRITICAL]`` / ``[HIGH]`` /
      ``[MEDIUM]`` badges and ``path/to/file.py:42`` locations)

    Honors Claude Security's adversarial verification panel by skipping findings
    explicitly marked ``verified: false``, ``confirmed: false``, ``mitigated: true``,
    or ``status`` in ``{"mitigated", "false_positive", "dismissed", "refuted"}``.

    Raises:
        ValueError: if a file is missing, unreadable, or malformed.
    """
    findings: list[Finding] = []
    files_ingested: list[str] = []
    formats_ingested: list[str] = []
    source_tools: list[str] = []
    total_raw = 0
    filtered_by_panel = 0
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    counter = 0

    for raw_path in paths:
        path = Path(raw_path)
        if not path.is_file():
            raise ValueError(f"Claude Security report file not found: {path}")

        try:
            raw_text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"Failed to read Claude Security report {path}: {exc}") from exc

        stripped = raw_text.strip()
        if not stripped:
            raise ValueError(f"Empty Claude Security report file: {path}")

        suffix = path.suffix.lower()
        looks_like_json = (
            suffix in {".json", ".sarif", ".jsonl", ".ndjson"} or stripped[0] in {"{", "["}
        )

        if looks_like_json:
            try:
                data = json.loads(stripped)
                if suffix in {".jsonl", ".ndjson"} and isinstance(data, dict):
                    # A one-finding JSONL file is also a valid JSON object.
                    data = [data]
            except json.JSONDecodeError as exc:
                # claude-security writes CLAUDE-SECURITY-RESULTS.jsonl: one
                # finding object per line. Fall back to JSONL before failing.
                data = _parse_jsonl_findings(stripped)
                if data is None:
                    raise ValueError(
                        f"Malformed JSON in Claude Security report {path}: {exc.msg}"
                    ) from exc

            # SARIF 2.1.0 delegation
            if (
                isinstance(data, dict)
                and str(data.get("version", "")).startswith("2.1")
                and isinstance(data.get("runs"), list)
            ):
                sarif_findings, sarif_tools = ingest_sarif_files([path])
                files_ingested.append(_norm_path(path))
                if "sarif" not in formats_ingested:
                    formats_ingested.append("sarif")
                for tool in sarif_tools:
                    if tool not in source_tools:
                        source_tools.append(tool)
                for sf in sarif_findings:
                    total_raw += 1
                    counter += 1
                    sev = "high" if sf.confidence >= 0.85 else "medium"
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    findings.append(
                        _build_finding(
                            finding_id=sf.id,
                            category="claude_security_plugin",
                            title=sf.title,
                            description=sf.description,
                            file_path=sf.file_path,
                            confidence=sf.confidence,
                            compliance_impact="gap",
                            compliance_dimensions=["security", "access_control", "risk_mgmt"],
                            evidence_snippet=sf.evidence_snippet,
                            article_paragraphs=["Art. 15(4)", "Art. 9(2)"],
                            severity=sev,
                            line_number=sf.line_number,
                        )
                    )
                continue

            json_findings, raw_n, filt_n, sev_n = _ingest_claude_security_json(data, path, counter)
            counter += len(json_findings)
            total_raw += raw_n
            filtered_by_panel += filt_n
            for k, v in sev_n.items():
                severity_counts[k] = severity_counts.get(k, 0) + v
            findings.extend(json_findings)
            files_ingested.append(_norm_path(path))
            if "json" not in formats_ingested:
                formats_ingested.append("json")
            if "claude-security" not in source_tools:
                source_tools.append("claude-security")
        elif suffix in {".md", ".markdown", ".txt"}:
            md_findings, raw_n, filt_n, sev_n = _ingest_claude_security_markdown(raw_text, path, counter)
            counter += len(md_findings)
            total_raw += raw_n
            filtered_by_panel += filt_n
            for k, v in sev_n.items():
                severity_counts[k] = severity_counts.get(k, 0) + v
            findings.extend(md_findings)
            files_ingested.append(_norm_path(path))
            if "markdown" not in formats_ingested:
                formats_ingested.append("markdown")
            if "claude-security" not in source_tools:
                source_tools.append("claude-security")
        else:
            raise ValueError(
                f"Unsupported Claude Security report format in {path}: expected SARIF, JSON, or Markdown"
            )

    metadata: dict[str, Any] = {
        "source": "claude_code_security",
        "files_ingested": files_ingested,
        "formats_ingested": formats_ingested,
        "source_tools": source_tools,
        "total_raw_findings": total_raw,
        "confirmed_findings": len(findings),
        "filtered_by_adversarial_panel": filtered_by_panel,
        "severity_counts": severity_counts,
    }
    return findings, metadata


__all__ = [
    "ingest_compliance_api_export",
    "ingest_claude_security_report",
]
