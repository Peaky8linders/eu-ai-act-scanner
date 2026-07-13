#!/usr/bin/env python3
"""Regenerate the date-relative EU AI Act enforcement countdown in README.md.

Rather than hard-code "T-100 days" (which rots), this computes the days
remaining from *today* and rewrites three managed regions of README.md:

* the countdown shields.io badge — between ``<!-- countdown-badge -->`` markers,
* the milestone table — between ``<!-- countdown-table:start/end -->`` markers,
* the illustrative "T-N days to Article 50 transparency enforcement" sample line.

Run manually (``python scripts/update_readme_countdown.py``) or on a schedule
(see ``.github/workflows/update-countdown.yml``, which commits any change). Pass
``--check`` to print the current values without writing.

Milestone dates reflect the **Digital Omnibus** (adopted 29 June 2026): the
high-risk Annex III regime was deferred to 2 December 2027, but Article 50
transparency was left at 2 August 2026 — the sharpest live deadline.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"


@dataclass(frozen=True)
class Milestone:
    label: str
    day: date
    articles: str
    headline: bool = False  # the one the badge + sample line track


MILESTONES: list[Milestone] = [
    Milestone("Prohibited practices", date(2025, 2, 2), "Art. 5"),
    Milestone("GPAI model obligations", date(2025, 8, 2), "Art. 53 / 55"),
    Milestone("Transparency", date(2026, 8, 2), "Art. 50", headline=True),
    Milestone("High-risk (Annex III)", date(2027, 12, 2), "Art. 9-15 / 17 / 27"),
]

BADGE_RE = re.compile(r"<!-- countdown-badge -->.*?<!-- /countdown-badge -->", re.DOTALL)
TABLE_RE = re.compile(
    r"<!-- countdown-table:start -->.*?<!-- countdown-table:end -->", re.DOTALL
)
SAMPLE_RE = re.compile(r"T-\d+ days to Article 50 transparency enforcement")


def _headline() -> Milestone:
    return next(m for m in MILESTONES if m.headline)


def _days(target: date, today: date) -> int:
    return (target - today).days


def _fmt_date(d: date) -> str:
    # Avoid platform-specific strftime (%-d / %#d); build it portably.
    return f"{d.day} {d.strftime('%b')} {d.year}"


def _status(m: Milestone, today: date) -> str:
    d = _days(m.day, today)
    if d < 0:
        return "✅ in force"
    if d == 0:
        return "⏳ **today**"
    return f"⏳ **T-{d} days**" if m.headline else f"⏳ T-{d} days"


def render_badge(today: date) -> str:
    d = _days(_headline().day, today)
    if d < 0:
        url = "https://img.shields.io/badge/Art.%2050%20transparency-in%20force-brightgreen"
    else:
        msg = f"T--{d}%20days%20(2%20Aug%202026)"
        url = f"https://img.shields.io/badge/Art.%2050%20transparency-{msg}-red"
    return f"<!-- countdown-badge -->![Article 50 countdown]({url})<!-- /countdown-badge -->"


def render_table(today: date) -> str:
    rows = [
        "<!-- countdown-table:start -->",
        "| Milestone | Articles | Date | Status |",
        "|---|---|---|---|",
    ]
    for m in MILESTONES:
        label = f"**{m.label}**" if m.headline else m.label
        rows.append(f"| {label} | {m.articles} | {_fmt_date(m.day)} | {_status(m, today)} |")
    rows.append("")
    rows.append(
        f"_Countdown generated {today.isoformat()} by "
        "`scripts/update_readme_countdown.py` (refreshed weekly in CI). The Digital "
        "Omnibus deferred high-risk to Dec 2027 but left Article 50 at 2 Aug 2026._"
    )
    rows.append("<!-- countdown-table:end -->")
    return "\n".join(rows)


def update(text: str, today: date) -> str:
    """Return ``text`` with all managed countdown regions refreshed for ``today``."""
    text = BADGE_RE.sub(lambda _m: render_badge(today), text)
    text = TABLE_RE.sub(lambda _m: render_table(today), text)
    days = max(_days(_headline().day, today), 0)
    text = SAMPLE_RE.sub(f"T-{days} days to Article 50 transparency enforcement", text)
    return text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Regenerate the README enforcement countdown.")
    ap.add_argument("--check", action="store_true", help="Print current values, do not write.")
    args = ap.parse_args(argv)

    today = date.today()
    for m in MILESTONES:
        d = _days(m.day, today)
        print(f"{m.label:<24} {_fmt_date(m.day):<14} {'in force' if d < 0 else f'T-{d} days'}")

    if args.check:
        return 0

    original = README.read_text(encoding="utf-8")
    updated = update(original, today)
    if updated != original:
        README.write_text(updated, encoding="utf-8")
        print(f"\nUpdated {README.name} countdown ({today.isoformat()}).")
    else:
        print(f"\n{README.name} countdown already current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
