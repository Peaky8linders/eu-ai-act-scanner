"""Opt-in local fetcher for the Anthropic Claude Compliance API.

Pulls paginated, read-only organizational audit metadata from Anthropic's
Claude Compliance API (``https://api.anthropic.com/v1/compliance/*``) and
writes an atomic local JSON snapshot ready for offline EU AI Act ingestion:

    python scripts/fetch_claude_compliance.py --output compliance-api-export.json
    eu-ai-act-scan . --ingest-compliance-api compliance-api-export.json --dossier release-dossier.json

Security & Privacy Guarantees:
- Lives in ``scripts/`` (outside ``scanner/``); the core scanner stays 100% offline.
- Pure Python stdlib (``urllib.request``) — zero third-party dependencies.
- Strictly validates that every request targets ``https://api.anthropic.com/v1/compliance/*``.
- Reads ``ANTHROPIC_COMPLIANCE_ACCESS_KEY`` (or fallback ``ANTHROPIC_ADMIN_API_KEY``
  for activities-only) from environment variables ONLY — never accepted as a CLI
  argument (prevents shell-history leaks) and never printed or written to disk.
- Strictly read-only ``GET`` requests — NEVER reads, uploads, or transmits any
  repository source code, prompts, or local files.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ANTHROPIC_API_BASE = "https://api.anthropic.com"
ANTHROPIC_COMPLIANCE_VERSION = "2026-10-21"
_SAFE_PATH_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

_SETUP_INSTRUCTIONS = """\
Missing Anthropic Compliance API credentials.

Set one of the following environment variables (never pass keys on the CLI):
  - ANTHROPIC_COMPLIANCE_ACCESS_KEY (recommended — full Compliance API access)
  - ANTHROPIC_ADMIN_API_KEY         (fallback — /v1/compliance/activities only)

How to create a Compliance Access Key:
  1. Open claude.ai and go to: Organization settings > Data and privacy
  2. Generate a Compliance Access Key with the required read-only scopes:
       - read:compliance_activities  (/v1/compliance/activities)
       - read:compliance_org_data    (/v1/compliance/groups)
       - read:compliance_user_data   (/v1/compliance/organizations/{org_uuid}/user_preferences,
                                      /v1/compliance/apps/sessions/remote/{id}/messages)
  3. Export it in your shell before running this script:
       export ANTHROPIC_COMPLIANCE_ACCESS_KEY="sk-ant-..."   # macOS / Linux
       $env:ANTHROPIC_COMPLIANCE_ACCESS_KEY = "sk-ant-..."   # PowerShell

Tip: Run with --dry-run to preview the exact endpoints without an API key or network call.
"""


def _validate_path_token(value: str, label: str) -> str:
    cleaned = value.strip()
    if not _SAFE_PATH_TOKEN_RE.match(cleaned) or ".." in cleaned:
        raise ValueError(
            f"Invalid {label} {value!r}: only alphanumeric characters, '.', '_', and '-' are allowed."
        )
    return urllib.parse.quote(cleaned, safe="")


def _validate_endpoint_url(url: str) -> str:
    """Enforce that every outbound request strictly targets https://api.anthropic.com/v1/compliance/*."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Refusing non-HTTPS URL: {url}")
    if parsed.netloc != "api.anthropic.com":
        raise ValueError(f"Refusing unexpected host {parsed.netloc!r}; only api.anthropic.com is allowed.")
    if not parsed.path.startswith("/v1/compliance/"):
        raise ValueError(f"Refusing non-compliance path {parsed.path!r}.")
    return url


def _build_endpoint_plan(
    *,
    org_uuid: str | None,
    remote_session_ids: list[str],
    limit: int,
    activities_only: bool = False,
) -> list[dict[str, str]]:
    """Build the ordered list of Compliance API endpoints to query."""
    query = urllib.parse.urlencode({"limit": limit})
    plan: list[dict[str, str]] = [
        {
            "resource": "activities",
            "scope": "read:compliance_activities",
            "url": _validate_endpoint_url(f"{ANTHROPIC_API_BASE}/v1/compliance/activities?{query}"),
        }
    ]

    if activities_only:
        return plan

    plan.append(
        {
            "resource": "groups",
            "scope": "read:compliance_org_data",
            "url": _validate_endpoint_url(f"{ANTHROPIC_API_BASE}/v1/compliance/groups?{query}"),
        }
    )

    if org_uuid:
        safe_org = _validate_path_token(org_uuid, "org-uuid")
        plan.append(
            {
                "resource": "user_preferences",
                "scope": "read:compliance_user_data",
                "url": _validate_endpoint_url(
                    f"{ANTHROPIC_API_BASE}/v1/compliance/organizations/{safe_org}/user_preferences?{query}"
                ),
            }
        )

    for session_id in remote_session_ids:
        safe_sid = _validate_path_token(session_id, "remote-session-id")
        plan.append(
            {
                "resource": "remote_sessions",
                "session_id": session_id.strip(),
                "scope": "read:compliance_user_data",
                "url": _validate_endpoint_url(
                    f"{ANTHROPIC_API_BASE}/v1/compliance/apps/sessions/remote/{safe_sid}/messages?{query}"
                ),
            }
        )

    return plan


def _append_cursor(base_url: str, cursor: str, *, param: str = "after_id") -> str:
    parsed = urllib.parse.urlparse(base_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params[param] = cursor
    new_query = urllib.parse.urlencode(params)
    return _validate_endpoint_url(urllib.parse.urlunparse(parsed._replace(query=new_query)))


def _next_page_url(base_url: str, payload: dict[str, Any]) -> str | None:
    """Return the next page URL for a Compliance API response, or None when done.

    The Compliance API uses three pagination shapes:

    * activities / chats: ``has_more`` + ``last_id`` -> request ``after_id=<last_id>``;
    * organizations, users, roles, groups, user_preferences: ``has_more`` +
      ``next_page`` -> request ``page=<next_page>``;
    * sessions and session messages: ``next_page`` only (no ``has_more``) ->
      request ``page=<next_page>`` until it is null.
    """
    next_page = payload.get("next_page")
    if isinstance(next_page, str) and next_page.strip():
        if payload.get("has_more") is False:
            return None
        return _append_cursor(base_url, next_page.strip(), param="page")
    if isinstance(next_page, int) and not isinstance(next_page, bool):
        if payload.get("has_more") is False:
            return None
        return _append_cursor(base_url, str(next_page), param="page")
    last_id = payload.get("last_id")
    if payload.get("has_more") is True and isinstance(last_id, str) and last_id.strip():
        return _append_cursor(base_url, last_id.strip(), param="after_id")
    return None


def _fetch_paginated_endpoint(
    url: str,
    api_key: str,
    *,
    max_pages: int,
    timeout: int = 30,
) -> list[dict[str, Any]]:
    """Fetch up to ``max_pages`` pages from a single validated Compliance API endpoint."""
    items: list[dict[str, Any]] = []
    current_url = _validate_endpoint_url(url)

    for _page in range(max_pages):
        req = urllib.request.Request(
            current_url,
            method="GET",
            headers={
                "x-api-key": api_key,
                "anthropic-version": ANTHROPIC_COMPLIANCE_VERSION,
                "accept": "application/json",
                "user-agent": "eu-ai-act-scanner-compliance-fetcher/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL validated above)
            raw = resp.read().decode("utf-8")

        payload = json.loads(raw)
        if isinstance(payload, dict):
            page_data = payload.get("data")
            if isinstance(page_data, list):
                items.extend(entry for entry in page_data if isinstance(entry, dict))
            elif payload:
                items.append(payload)

            next_url = _next_page_url(url, payload)
            if next_url is None or next_url == current_url:
                break
            current_url = next_url
        elif isinstance(payload, list):
            items.extend(entry for entry in payload if isinstance(entry, dict))
            break
        else:
            break

    return items


def _write_json_atomic(target: Path, payload: dict[str, Any]) -> None:
    """Write JSON atomically via a sibling temp file + os.replace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(serialized)
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fetch_claude_compliance.py",
        description=(
            "Opt-in local fetcher for the Anthropic Claude Compliance API "
            "(https://api.anthropic.com/v1/compliance/*). Never uploads repository code."
        ),
    )
    parser.add_argument(
        "--output",
        default="compliance-api-export.json",
        help="Destination path for the local JSON snapshot (default: compliance-api-export.json).",
    )
    parser.add_argument(
        "--org-uuid",
        default=None,
        help="Organization UUID to also fetch /v1/compliance/organizations/{org_uuid}/user_preferences.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Items requested per page (1-1000, default: 100).",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=5,
        help="Maximum pagination pages per endpoint (1-100, default: 5).",
    )
    parser.add_argument(
        "--remote-session-id",
        action="append",
        default=[],
        help=(
            "Optional remote session ID to fetch /v1/compliance/apps/sessions/remote/{id}/messages. "
            "May be passed multiple times."
        ),
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=None,
        help="Optional organization audit log retention window in days (recorded in snapshot for Art. 26(6) check).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the exact Compliance API endpoints and headers plan without making network calls.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not (1 <= args.limit <= 1000):
        print("Error: --limit must be between 1 and 1000.", file=sys.stderr)
        return 2
    if not (1 <= args.max_pages <= 100):
        print("Error: --max-pages must be between 1 and 100.", file=sys.stderr)
        return 2
    if args.retention_days is not None and args.retention_days < 0:
        print("Error: --retention-days must be >= 0.", file=sys.stderr)
        return 2

    if args.dry_run:
        try:
            plan = _build_endpoint_plan(
                org_uuid=args.org_uuid,
                remote_session_ids=list(args.remote_session_id or []),
                limit=args.limit,
                activities_only=False,
            )
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

        print("Dry run — no network calls made, no API key read, no repository code touched.")
        print(f"Base URL:          {ANTHROPIC_API_BASE}")
        print(f"anthropic-version: {ANTHROPIC_COMPLIANCE_VERSION}")
        print("Auth header:       x-api-key: $ANTHROPIC_COMPLIANCE_ACCESS_KEY")
        print(f"Max pages/endpoint:{args.max_pages}")
        print(f"Output path:       {args.output}")
        print("Endpoints:")
        for entry in plan:
            print(f"  GET {entry['url']}  [scope: {entry['scope']}]")
        return 0

    compliance_key = os.environ.get("ANTHROPIC_COMPLIANCE_ACCESS_KEY", "").strip()
    admin_key = os.environ.get("ANTHROPIC_ADMIN_API_KEY", "").strip()

    activities_only = False
    if compliance_key:
        api_key = compliance_key
    elif admin_key:
        api_key = admin_key
        activities_only = True
        print(
            "Notice: ANTHROPIC_COMPLIANCE_ACCESS_KEY not set; falling back to "
            "ANTHROPIC_ADMIN_API_KEY (activities endpoint only).",
            file=sys.stderr,
        )
    else:
        print(_SETUP_INSTRUCTIONS, file=sys.stderr)
        return 2

    try:
        plan = _build_endpoint_plan(
            org_uuid=args.org_uuid,
            remote_session_ids=list(args.remote_session_id or []),
            limit=args.limit,
            activities_only=activities_only,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    activities: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    user_preferences: list[dict[str, Any]] = []
    remote_sessions: list[dict[str, Any]] = []
    endpoints_queried: list[str] = []

    for entry in plan:
        endpoint_url = entry["url"]
        resource = entry["resource"]
        try:
            records = _fetch_paginated_endpoint(endpoint_url, api_key, max_pages=args.max_pages)
        except urllib.error.HTTPError as exc:
            print(
                f"HTTP {exc.code} fetching {urllib.parse.urlparse(endpoint_url).path} "
                f"(scope: {entry['scope']}): {exc.reason}",
                file=sys.stderr,
            )
            return 1
        except urllib.error.URLError as exc:
            print(f"Network error fetching {urllib.parse.urlparse(endpoint_url).path}: {exc.reason}", file=sys.stderr)
            return 1

        endpoints_queried.append(urllib.parse.urlparse(endpoint_url).path)
        if resource == "activities":
            activities.extend(records)
        elif resource == "groups":
            groups.extend(records)
        elif resource == "user_preferences":
            user_preferences.extend(records)
        elif resource == "remote_sessions":
            remote_sessions.append(
                {
                    "session_id": entry.get("session_id", "remote-session"),
                    "messages": records,
                }
            )

    snapshot: dict[str, Any] = {
        "schema_version": "1.0",
        "source": "anthropic_claude_compliance_api",
        "api_version": ANTHROPIC_COMPLIANCE_VERSION,
        "fetched_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "organization_uuid": args.org_uuid,
        "retention_days": args.retention_days,
        "endpoints_queried": endpoints_queried,
        "activities": activities,
        "groups": groups,
        "user_preferences": user_preferences,
        "remote_sessions": remote_sessions,
    }

    output_path = Path(args.output)
    _write_json_atomic(output_path, snapshot)

    print(
        f"Wrote Claude Compliance API snapshot to {output_path} "
        f"(activities={len(activities)}, groups={len(groups)}, "
        f"user_preferences={len(user_preferences)}, remote_sessions={len(remote_sessions)})."
    )
    print(
        f"Next step (100% offline): "
        f"eu-ai-act-scan . --ingest-compliance-api {output_path} --dossier release-dossier.json"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
