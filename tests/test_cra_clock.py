"""CRA Art. 14 reporting clock (Regulation (EU) 2024/2847).

The clock turns "when did we become aware" into the dates a manufacturer has
to meet. A wrong date here is a missed statutory deadline, so each test pins
one rule of Art. 14(2) or 14(4) and fails if the arithmetic drifts:

* 24 hours and 72 hours are elapsed time from awareness, also across a
  daylight-saving change (a wall-clock "same time tomorrow" is an hour late
  in autumn);
* the final report is anchored differently per event type: 14 days after a
  corrective or mitigating measure is available for an actively exploited
  vulnerability (Art. 14(2)(c)), one month after the incident notification
  was submitted for a severe incident (Art. 14(4)(c));
* the clock computes deadlines only. It never states that anything was filed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from scanner.cra import Art14Event, article_14_clock, format_article_14_clock

BRUSSELS = ZoneInfo("Europe/Brussels")


# ─── 24h / 72h: both event types ────────────────────────────────────────


def test_vulnerability_early_warning_and_notification_deadlines() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    clock = article_14_clock(aware, Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY)

    assert clock.early_warning_due == datetime(2026, 11, 4, 9, 30, tzinfo=UTC)
    assert clock.notification_due == datetime(2026, 11, 6, 9, 30, tzinfo=UTC)
    assert clock.early_warning_citation == "CRA Art. 14(2)(a)"
    assert clock.notification_citation == "CRA Art. 14(2)(b)"
    assert clock.final_report_citation == "CRA Art. 14(2)(c)"


def test_severe_incident_uses_the_paragraph_4_citations() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    clock = article_14_clock(aware, Art14Event.SEVERE_INCIDENT)

    assert clock.early_warning_due - aware == timedelta(hours=24)
    assert clock.notification_due - aware == timedelta(hours=72)
    assert clock.early_warning_citation == "CRA Art. 14(4)(a)"
    assert clock.notification_citation == "CRA Art. 14(4)(b)"
    assert clock.final_report_citation == "CRA Art. 14(4)(c)"


def test_event_type_accepts_its_string_value() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    assert article_14_clock(aware, "severe_incident").event_type is Art14Event.SEVERE_INCIDENT
    with pytest.raises(ValueError, match="event_type"):
        article_14_clock(aware, "data_breach")


# ─── Daylight-saving boundaries ─────────────────────────────────────────


def test_24_hours_is_elapsed_time_when_clocks_go_back() -> None:
    """Summer time ends on 25 Oct 2026. Noon on the 24th plus 24 elapsed hours
    is 11:00 on the 25th in Brussels; "noon the next day" would be 25 hours."""
    aware = datetime(2026, 10, 24, 12, 0, tzinfo=BRUSSELS)
    clock = article_14_clock(aware, Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY)

    assert clock.early_warning_due.astimezone(UTC) == datetime(2026, 10, 25, 10, 0, tzinfo=UTC)
    assert clock.early_warning_due.astimezone(UTC) - aware.astimezone(UTC) == timedelta(hours=24)
    # Reported in the caller's zone, on the new offset.
    assert clock.early_warning_due.isoformat() == "2026-10-25T11:00:00+01:00"
    assert clock.notification_due.isoformat() == "2026-10-27T11:00:00+01:00"


def test_24_hours_is_elapsed_time_when_clocks_go_forward() -> None:
    """Summer time starts on 28 Mar 2027: 24 elapsed hours after noon on the
    27th is 13:00 on the 28th in Brussels."""
    aware = datetime(2027, 3, 27, 12, 0, tzinfo=BRUSSELS)
    clock = article_14_clock(aware, Art14Event.SEVERE_INCIDENT)

    assert clock.early_warning_due.isoformat() == "2027-03-28T13:00:00+02:00"
    assert clock.notification_due.astimezone(UTC) - aware.astimezone(UTC) == timedelta(hours=72)


def test_naive_awareness_time_is_refused() -> None:
    """Without an offset the same wall time is a different instant in every
    Member State, so the deadline would be a guess."""
    with pytest.raises(ValueError, match="UTC offset"):
        article_14_clock(datetime(2026, 11, 3, 9, 30), Art14Event.SEVERE_INCIDENT)


# ─── Final report: actively exploited vulnerability ─────────────────────


def test_vulnerability_final_report_is_open_until_a_measure_is_available() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    clock = article_14_clock(aware, Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY)

    assert clock.final_report_due is None
    assert "14 days after a corrective or mitigating measure is available" in clock.final_report_rule


def test_vulnerability_final_report_is_14_days_after_the_measure() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    measure = datetime(2026, 11, 10, 16, 0, tzinfo=UTC)
    clock = article_14_clock(
        aware, Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY, measure_available_at=measure
    )

    assert clock.final_report_due == datetime(2026, 11, 24, 16, 0, tzinfo=UTC)


def test_14_days_never_lands_on_the_fifteenth_calendar_day() -> None:
    """A measure available late on 20 Mar 2027 (Brussels): 14 x 24 elapsed
    hours ends at 00:30 on 4 Apr because one day in between has 23 hours.
    The deadline stays on 3 Apr, the fourteenth day."""
    aware = datetime(2027, 3, 18, 9, 0, tzinfo=BRUSSELS)
    measure = datetime(2027, 3, 20, 23, 30, tzinfo=BRUSSELS)
    clock = article_14_clock(
        aware, Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY, measure_available_at=measure
    )

    assert clock.final_report_due is not None
    assert clock.final_report_due.isoformat() == "2027-04-03T23:30:00+02:00"


def test_measure_that_predates_awareness_gets_no_computed_date() -> None:
    """A fix can exist before exploitation is discovered. Art. 14(2)(c) does
    not say how the 14 days run then, so the clock gives no date."""
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    clock = article_14_clock(
        aware,
        Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY,
        measure_available_at=aware - timedelta(days=30),
    )

    assert clock.final_report_due is None
    assert any("before" in note for note in clock.notes)


# ─── Final report: severe incident ──────────────────────────────────────


def test_incident_final_report_is_open_until_the_notification_time_is_known() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    clock = article_14_clock(aware, Art14Event.SEVERE_INCIDENT)

    assert clock.final_report_due is None
    assert "one month after the submission of the incident notification" in clock.final_report_rule


def test_incident_final_report_is_one_calendar_month_after_the_notification() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    sent = datetime(2026, 11, 5, 14, 0, tzinfo=UTC)
    clock = article_14_clock(aware, Art14Event.SEVERE_INCIDENT, notification_submitted_at=sent)

    assert clock.final_report_due == datetime(2026, 12, 5, 14, 0, tzinfo=UTC)


def test_one_month_clamps_to_the_last_day_of_a_shorter_month() -> None:
    aware = datetime(2027, 1, 29, 8, 0, tzinfo=UTC)
    sent = datetime(2027, 1, 31, 10, 0, tzinfo=UTC)
    clock = article_14_clock(aware, Art14Event.SEVERE_INCIDENT, notification_submitted_at=sent)

    assert clock.final_report_due == datetime(2027, 2, 28, 10, 0, tzinfo=UTC)


def test_one_month_across_the_year_end() -> None:
    aware = datetime(2026, 12, 14, 8, 0, tzinfo=timezone(timedelta(hours=1)))
    sent = datetime(2026, 12, 15, 8, 0, tzinfo=timezone(timedelta(hours=1)))
    clock = article_14_clock(aware, Art14Event.SEVERE_INCIDENT, notification_submitted_at=sent)

    assert clock.final_report_due is not None
    assert clock.final_report_due.isoformat() == "2027-01-15T08:00:00+01:00"


# ─── Anchors belong to one event type each ──────────────────────────────


def test_each_anchor_is_refused_for_the_other_event_type() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    later = aware + timedelta(days=2)
    with pytest.raises(ValueError, match="measure_available_at"):
        article_14_clock(aware, Art14Event.SEVERE_INCIDENT, measure_available_at=later)
    with pytest.raises(ValueError, match="notification_submitted_at"):
        article_14_clock(
            aware, Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY, notification_submitted_at=later
        )


def test_notification_cannot_precede_awareness() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    with pytest.raises(ValueError, match="before the awareness time"):
        article_14_clock(
            aware, Art14Event.SEVERE_INCIDENT, notification_submitted_at=aware - timedelta(hours=1)
        )


def test_naive_anchor_is_refused() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    with pytest.raises(ValueError, match="UTC offset"):
        article_14_clock(
            aware,
            Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY,
            measure_available_at=datetime(2026, 11, 10, 16, 0),
        )


# ─── Application date ───────────────────────────────────────────────────


def test_awareness_before_article_14_applied_is_flagged() -> None:
    """Art. 14 applies from 11 September 2026 (Art. 71(2))."""
    before = article_14_clock(datetime(2026, 9, 1, 9, 0, tzinfo=UTC), Art14Event.SEVERE_INCIDENT)
    after = article_14_clock(datetime(2026, 9, 11, 9, 0, tzinfo=UTC), Art14Event.SEVERE_INCIDENT)

    assert any("11 September 2026" in note for note in before.notes)
    assert not any("11 September 2026" in note for note in after.notes)


# ─── It is a calculator, never a filing record ──────────────────────────


@pytest.mark.parametrize("event", list(Art14Event))
def test_clock_never_claims_a_notification_was_filed(event: Art14Event) -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    anchors = (
        {"measure_available_at": aware + timedelta(days=3)}
        if event is Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY
        else {"notification_submitted_at": aware + timedelta(days=2)}
    )
    for clock in (article_14_clock(aware, event), article_14_clock(aware, event, **anchors)):
        assert clock.files_notifications is False
        text = format_article_14_clock(clock).lower()
        assert "does not file" in text
        for claim in ("has been filed", "was filed", "has been notified", "were notified",
                      "notification sent to", "met the deadline", "compliant"):
            assert claim not in text, claim


def test_formatted_clock_names_the_recipients_and_cites_the_article() -> None:
    clock = article_14_clock(
        datetime(2026, 10, 24, 12, 0, tzinfo=BRUSSELS), Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY
    )
    text = format_article_14_clock(clock)

    assert "2026-10-25T11:00:00+01:00" in text
    assert "CRA Art. 14(2)(a)" in text
    assert "single reporting platform" in text
    assert "CSIRT" in text and "ENISA" in text


def test_clock_is_deterministic_and_serialises() -> None:
    aware = datetime(2026, 11, 3, 9, 30, tzinfo=UTC)
    first = article_14_clock(aware, Art14Event.SEVERE_INCIDENT)
    second = article_14_clock(aware, Art14Event.SEVERE_INCIDENT)

    assert first == second
    payload = first.to_dict()
    assert payload["early_warning_due"] == "2026-11-04T09:30:00+00:00"
    assert payload["event_type"] == "severe_incident"
    assert payload["files_notifications"] is False
