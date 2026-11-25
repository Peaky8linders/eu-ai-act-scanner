"""CRA Art. 14 reporting clock: Regulation (EU) 2024/2847.

A pure calculator. Given when the manufacturer became aware and what kind of
event it is, it returns the dates Art. 14 sets:

* early warning within 24 hours of becoming aware: Art. 14(2)(a) / 14(4)(a);
* notification within 72 hours of becoming aware: Art. 14(2)(b) / 14(4)(b);
* final report: no later than 14 days after a corrective or mitigating
  measure is available for an actively exploited vulnerability
  (Art. 14(2)(c)); within one month after the incident notification was
  submitted for a severe incident (Art. 14(4)(c)).

Art. 14 applies from 11 September 2026 (Art. 71(2)).

It reads no clock, no file and no network, and it never records or claims that
a notification was made. Filing happens on the single reporting platform
(Art. 14(7), Art. 16), outside this tool.

How periods are counted here, always choosing the earlier reading:

* hours are elapsed time from the awareness instant, so a daylight-saving
  change neither adds nor removes an hour;
* 14 days is the earlier of 14 x 24 elapsed hours and the same wall-clock time
  14 calendar days later in the caller's time zone;
* one month is the same day and wall-clock time in the next calendar month,
  moved back to the last day when that month is shorter.

Whether a legal period ends later than these dates (rules on the calculation
of periods, weekends, public holidays) is a question for counsel. The clock
does not extend a deadline on that basis.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum

REGULATION = "Regulation (EU) 2024/2847 (Cyber Resilience Act)"

# Art. 71(2): Art. 14 applies from this date; the rest from 11 December 2027.
ARTICLE_14_APPLIES_FROM = date(2026, 9, 11)
FULL_APPLICATION_FROM = date(2027, 12, 11)

EARLY_WARNING_WINDOW = timedelta(hours=24)
NOTIFICATION_WINDOW = timedelta(hours=72)
FINAL_REPORT_DAYS_AFTER_MEASURE = 14

RECIPIENTS = (
    "the CSIRT designated as coordinator and ENISA, through the single reporting "
    "platform (CRA Art. 14(1), 14(3), 14(7) and Art. 16)"
)
NOT_A_FILING_RECORD = (
    "This is a deadline calculation only. The scanner does not file, send or "
    "confirm any notification."
)


class Art14Event(StrEnum):
    """The two events Art. 14 makes reportable."""

    ACTIVELY_EXPLOITED_VULNERABILITY = "actively_exploited_vulnerability"  # Art. 14(1)-(2)
    SEVERE_INCIDENT = "severe_incident"  # Art. 14(3)-(4)


_PARAGRAPH = {
    Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY: "2",
    Art14Event.SEVERE_INCIDENT: "4",
}
_FINAL_REPORT_RULE = {
    Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY: (
        "No later than 14 days after a corrective or mitigating measure is available."
    ),
    Art14Event.SEVERE_INCIDENT: (
        "Within one month after the submission of the incident notification."
    ),
}


@dataclass(frozen=True)
class Art14Clock:
    """Deadlines for one reportable event. Dates are in the caller's time zone."""

    event_type: Art14Event
    aware_at: datetime
    early_warning_due: datetime
    early_warning_citation: str
    notification_due: datetime
    notification_citation: str
    # None until the anchor is known: when a corrective or mitigating measure
    # became available (vulnerability), or when the incident notification was
    # submitted (severe incident).
    final_report_due: datetime | None
    final_report_rule: str
    final_report_citation: str
    recipients: str = RECIPIENTS
    notes: tuple[str, ...] = ()
    # Always False. Present so no consumer can read a clock as a filing record.
    files_notifications: bool = False

    def to_dict(self) -> dict:
        return {
            "regulation": REGULATION,
            "event_type": self.event_type.value,
            "aware_at": self.aware_at.isoformat(),
            "early_warning_due": self.early_warning_due.isoformat(),
            "early_warning_citation": self.early_warning_citation,
            "notification_due": self.notification_due.isoformat(),
            "notification_citation": self.notification_citation,
            "final_report_due": self.final_report_due.isoformat() if self.final_report_due else None,
            "final_report_rule": self.final_report_rule,
            "final_report_citation": self.final_report_citation,
            "recipients": self.recipients,
            "notes": list(self.notes),
            "files_notifications": self.files_notifications,
            "disclaimer": NOT_A_FILING_RECORD,
        }


def _require_offset(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(
            f"{name} needs a UTC offset or time zone (for example 2026-11-03T09:30:00+01:00); "
            "without one the deadline would be a guess."
        )


def _after_elapsed(start: datetime, delta: timedelta) -> datetime:
    """``start`` plus real elapsed time, reported in ``start``'s time zone.

    Adding a timedelta to a zone-aware datetime moves the wall clock, which is
    an hour off across a daylight-saving change. Going through UTC is exact.
    """
    return (start.astimezone(UTC) + delta).astimezone(start.tzinfo)


def _same_wall_time(start: datetime, target: date) -> datetime:
    """``start``'s wall-clock time on ``target``, normalised in its time zone."""
    wall = datetime.combine(target, start.time(), tzinfo=start.tzinfo)
    return wall.astimezone(UTC).astimezone(start.tzinfo)


def _fourteen_days_after(start: datetime) -> datetime:
    elapsed = _after_elapsed(start, timedelta(days=FINAL_REPORT_DAYS_AFTER_MEASURE))
    wall = _same_wall_time(start, start.date() + timedelta(days=FINAL_REPORT_DAYS_AFTER_MEASURE))
    return min(elapsed, wall)


def _one_month_after(start: datetime) -> datetime:
    year, month = (start.year + 1, 1) if start.month == 12 else (start.year, start.month + 1)
    day = min(start.day, calendar.monthrange(year, month)[1])
    return _same_wall_time(start, date(year, month, day))


def article_14_clock(
    aware_at: datetime,
    event_type: Art14Event | str,
    *,
    measure_available_at: datetime | None = None,
    notification_submitted_at: datetime | None = None,
) -> Art14Clock:
    """Deadlines under CRA Art. 14 for one event.

    Args:
        aware_at: when the manufacturer became aware. Must carry a UTC offset.
        event_type: an :class:`Art14Event` or its string value.
        measure_available_at: actively exploited vulnerability only. When a
            corrective or mitigating measure became available; anchors the
            final report (Art. 14(2)(c)).
        notification_submitted_at: severe incident only. When the 72-hour
            incident notification was submitted, as stated by the caller;
            anchors the final report (Art. 14(4)(c)). The clock does not check
            or record that a submission happened.

    Raises:
        ValueError: unknown event type, a time without an offset, an anchor
            given for the other event type, or a notification time before
            awareness.
    """
    try:
        event = Art14Event(event_type)
    except ValueError:
        accepted = ", ".join(e.value for e in Art14Event)
        raise ValueError(f"Unknown event_type {event_type!r}; expected one of: {accepted}") from None

    _require_offset(aware_at, "aware_at")
    is_vulnerability = event is Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY
    if measure_available_at is not None and not is_vulnerability:
        raise ValueError(
            "measure_available_at anchors the final report for an actively exploited "
            "vulnerability (Art. 14(2)(c)); a severe incident uses notification_submitted_at."
        )
    if notification_submitted_at is not None and is_vulnerability:
        raise ValueError(
            "notification_submitted_at anchors the final report for a severe incident "
            "(Art. 14(4)(c)); an actively exploited vulnerability uses measure_available_at."
        )

    notes: list[str] = []
    if aware_at.astimezone(UTC).date() < ARTICLE_14_APPLIES_FROM:
        notes.append(
            "Art. 14 applies from 11 September 2026 (Art. 71(2)); the awareness time given is earlier."
        )

    final_report_due: datetime | None = None
    if measure_available_at is not None:
        _require_offset(measure_available_at, "measure_available_at")
        if measure_available_at < aware_at:
            notes.append(
                "The measure was available before the awareness time. Art. 14(2)(c) does not say "
                "how the 14 days run in that case, so no final-report date is computed; take advice."
            )
        else:
            final_report_due = _fourteen_days_after(measure_available_at)
    if notification_submitted_at is not None:
        _require_offset(notification_submitted_at, "notification_submitted_at")
        if notification_submitted_at < aware_at:
            raise ValueError("notification_submitted_at is before the awareness time.")
        final_report_due = _one_month_after(notification_submitted_at)

    paragraph = _PARAGRAPH[event]
    return Art14Clock(
        event_type=event,
        aware_at=aware_at,
        early_warning_due=_after_elapsed(aware_at, EARLY_WARNING_WINDOW),
        early_warning_citation=f"CRA Art. 14({paragraph})(a)",
        notification_due=_after_elapsed(aware_at, NOTIFICATION_WINDOW),
        notification_citation=f"CRA Art. 14({paragraph})(b)",
        final_report_due=final_report_due,
        final_report_rule=_FINAL_REPORT_RULE[event],
        final_report_citation=f"CRA Art. 14({paragraph})(c)",
        notes=tuple(notes),
    )


_EVENT_LABEL = {
    Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY: "Actively exploited vulnerability",
    Art14Event.SEVERE_INCIDENT: "Severe incident",
}
_NOTIFICATION_LABEL = {
    Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY: "Vulnerability notification",
    Art14Event.SEVERE_INCIDENT: "Incident notification",
}
_OPEN_FINAL_REPORT = {
    Art14Event.ACTIVELY_EXPLOITED_VULNERABILITY: (
        "no date yet: give the time a corrective or mitigating measure became available"
    ),
    Art14Event.SEVERE_INCIDENT: (
        "no date yet: give the time the incident notification was submitted"
    ),
}


def format_article_14_clock(clock: Art14Clock) -> str:
    """Markdown rendering of a clock: the three steps, who receives them, the caveats."""
    final = clock.final_report_due.isoformat() if clock.final_report_due else _OPEN_FINAL_REPORT[clock.event_type]
    lines = [
        "# CRA Art. 14 reporting clock",
        "",
        f"**Event:** {_EVENT_LABEL[clock.event_type]}",
        f"**Became aware:** {clock.aware_at.isoformat()}",
        "",
        "| Step | Due by | Rule | Citation |",
        "|---|---|---|---|",
        f"| Early warning | {clock.early_warning_due.isoformat()} | within 24 hours of becoming aware | {clock.early_warning_citation} |",
        f"| {_NOTIFICATION_LABEL[clock.event_type]} | {clock.notification_due.isoformat()} | within 72 hours of becoming aware | {clock.notification_citation} |",
        f"| Final report | {final} | {clock.final_report_rule} | {clock.final_report_citation} |",
        "",
        f"**Goes to:** {clock.recipients}.",
        "",
        "The early warning and the notification are due without undue delay; 24 and 72 hours are the outer limits.",
    ]
    lines.extend(f"- Note: {note}" for note in clock.notes)
    lines.extend(["", NOT_A_FILING_RECORD])
    return "\n".join(lines)
