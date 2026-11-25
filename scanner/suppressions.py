"""Project suppressions: gaps a team has judged not applicable, each with a reason.

A founder who reads "no AI disclosure in app.py" and knows the notice lives in
the web frontend can say so once, in the scanned project's
``.antifragile-harness.toml``::

    [[suppress]]
    title = "AI-interaction disclosure"
    path = "app.py"
    reason = "The disclosure banner is rendered by our web frontend (separate repo)."

Each entry needs a ``reason`` and at least one matcher. Every matcher that is
set must match:

* ``analyzer`` — the analyzer id (``article_50_transparency``, ``security_controls``, ...)
* ``title`` — text the finding title contains, ignoring case
* ``path`` — a glob on the project-relative path (``src/legacy/*``), or a folder ending in ``/``
* ``area`` — a KB dimension id (``transparency``, ``logging``, ...)

Matching gaps are left out of scores and briefs, but listed in
``ScanResult.suppressed_findings`` with their reason, so the decision stays
visible and reviewable, and the reasons tell maintainers which rules misfire.
Only gaps can be suppressed: positive evidence and the AI-system scope gate
(which reads analyzer metadata, not gaps) are never affected. Nothing here
touches the network.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from fnmatch import fnmatchcase
from pathlib import Path

from scanner.analyzers import AnalyzerResult
from scanner.models import SuppressedFinding, SuppressionRule
from scanner.settings import project_config_path

MAX_RULES = 200
_MAX_FIELD = 300
_MATCHERS = ("analyzer", "title", "path", "area")
_KEYS = (*_MATCHERS, "reason")


def load_rules(root: str | Path) -> tuple[list[SuppressionRule], list[str]]:
    """Read the ``[[suppress]]`` entries of the project at *root*.

    Returns ``(rules, problems)``: the valid rules, and one plain-English line
    per entry that was ignored. A missing config file is not a problem.
    """
    path = project_config_path(root)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], []
    except (OSError, UnicodeDecodeError) as exc:
        return [], [f"Could not read {path.name} ({exc.__class__.__name__}); no suppressions were applied."]
    except tomllib.TOMLDecodeError as exc:
        return [], [f"{path.name} is not valid TOML ({exc}); no suppressions were applied."]

    entries = data.get("suppress", [])
    if not entries:
        return [], []
    if not isinstance(entries, list):
        return [], ["`suppress` must be written as [[suppress]] tables; no suppressions were applied."]

    from scanner.kb import DIMENSIONS  # lazy: kb is large and only needed when rules exist

    rules: list[SuppressionRule] = []
    problems: list[str] = []
    for number, entry in enumerate(entries[:MAX_RULES], start=1):
        label = f"[[suppress]] entry {number}"
        if not isinstance(entry, dict):
            problems.append(f"{label} is not a table, so it was ignored.")
            continue
        unknown = sorted(set(entry) - set(_KEYS))
        if unknown:
            problems.append(f"{label} has unknown key(s) {', '.join(unknown)}; they were ignored.")
        if any(key in entry and not isinstance(entry[key], str) for key in _KEYS):
            problems.append(f"{label} has a value that is not text, so it was ignored.")
            continue
        fields = {key: str(entry.get(key, "")).strip()[:_MAX_FIELD] for key in _KEYS}
        if not fields["reason"]:
            problems.append(f"{label} has no reason, so it was ignored. Say why the finding does not apply.")
            continue
        if not any(fields[key] for key in _MATCHERS):
            problems.append(f"{label} sets none of analyzer, title, path or area, so it was ignored.")
            continue
        if fields["area"] and fields["area"] not in DIMENSIONS:
            problems.append(f"{label} names an unknown area {fields['area']!r}, so it was ignored.")
            continue
        rules.append(SuppressionRule(**fields))
    if len(entries) > MAX_RULES:
        problems.append(f"Only the first {MAX_RULES} [[suppress]] entries are used.")
    return rules, problems


def _path_matches(pattern: str, file_path: str) -> bool:
    path = (file_path or "").replace("\\", "/").removeprefix("./")
    glob = pattern.replace("\\", "/").removeprefix("./")
    if glob.endswith("/"):
        return path.startswith(glob)
    return fnmatchcase(path, glob)


def rule_matches(
    rule: SuppressionRule,
    *,
    title: str,
    file_path: str = "",
    dimensions: Iterable[str] = (),
    analyzer: str | None = None,
) -> bool:
    """True when every matcher the rule sets matches.

    ``analyzer`` is ``None`` for items that carry no analyzer (the area-level
    items founder triage derives from low scores); a rule that names an
    analyzer never matches those.
    """
    if rule.analyzer and rule.analyzer != analyzer:
        return False
    if rule.title and rule.title.lower() not in (title or "").lower():
        return False
    if rule.path and not _path_matches(rule.path, file_path):
        return False
    return not (rule.area and rule.area not in set(dimensions))


def first_match(
    rules: Iterable[SuppressionRule],
    *,
    title: str,
    file_path: str = "",
    dimensions: Iterable[str] = (),
    analyzer: str | None = None,
) -> SuppressionRule | None:
    """The first rule that matches the item, or ``None``."""
    dims = list(dimensions)
    return next(
        (
            rule for rule in rules
            if rule_matches(rule, title=title, file_path=file_path, dimensions=dims, analyzer=analyzer)
        ),
        None,
    )


def apply_to_results(
    results: list[AnalyzerResult], rules: list[SuppressionRule]
) -> list[SuppressedFinding]:
    """Remove the gaps that a rule matches from *results*; return what was removed."""
    suppressed: list[SuppressedFinding] = []
    if not rules:
        return suppressed
    for result in results:
        kept = []
        for finding in result.findings:
            rule = None
            if finding.compliance_impact == "gap":
                rule = first_match(
                    rules,
                    title=finding.title,
                    file_path=finding.file_path,
                    dimensions=finding.compliance_dimensions,
                    analyzer=finding.category,
                )
            if rule is None:
                kept.append(finding)
                continue
            suppressed.append(SuppressedFinding(
                title=finding.title,
                analyzer=finding.category,
                file_path=finding.file_path,
                line_number=finding.line_number,
                reason=rule.reason,
            ))
        result.findings = kept
    return suppressed
