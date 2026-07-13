"""Tests for the README enforcement-countdown generator.

The countdown must (1) track Article 50 (2 Aug 2026) as the headline deadline —
NOT the deferred high-risk regime — (2) render past milestones as in-force and
future ones as a T-N count from a given date, and (3) be idempotent so the
weekly CI refresh only commits real changes. All tests pin a fixed date so they
never rot.
"""

from __future__ import annotations

from datetime import date

from scripts.update_readme_countdown import (
    MILESTONES,
    render_badge,
    render_table,
    update,
)

# 20 days before Article 50 enforcement (2 Aug 2026).
FIXED = date(2026, 7, 13)


def test_headline_is_article_50():
    headline = [m for m in MILESTONES if m.headline]
    assert len(headline) == 1
    assert headline[0].articles == "Art. 50"
    assert headline[0].day == date(2026, 8, 2)


def test_badge_counts_down_to_article_50():
    badge = render_badge(FIXED)
    assert "countdown-badge" in badge
    assert "T--20%20days" in badge  # 2 Aug 2026 − 13 Jul 2026 = 20


def test_badge_shows_in_force_once_past():
    badge = render_badge(date(2027, 1, 1))  # after Art. 50
    assert "in%20force" in badge


def test_table_marks_past_in_force_and_future_as_countdown():
    table = render_table(FIXED)
    assert "✅ in force" in table          # prohibited + GPAI are already past
    assert "⏳ **T-20 days**" in table      # Art. 50 headline row
    assert "T-507 days" in table           # high-risk, 2 Dec 2027
    assert "countdown-table:start" in table
    assert "countdown-table:end" in table


def test_update_replaces_all_regions_and_is_idempotent():
    src = (
        "x <!-- countdown-badge -->OLD<!-- /countdown-badge --> y\n"
        "<!-- countdown-table:start -->OLD<!-- countdown-table:end -->\n"
        "T-999 days to Article 50 transparency enforcement\n"
    )
    once = update(src, FIXED)
    assert "T-20 days to Article 50 transparency enforcement" in once
    assert "T-999" not in once
    assert "T--20%20days" in once
    # Re-running against an already-current file is a no-op.
    assert update(once, FIXED) == once
