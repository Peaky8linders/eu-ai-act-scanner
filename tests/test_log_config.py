"""Console logging for the CLI, fix loop and MCP server (scanner.log_config).

Log events must go to stderr, because stdout carries the JSON/markdown payload
or the MCP messages. They must also follow stderr when a host swaps it: binding
the stream once at configure time broke every later log call after pytest's
``capsys`` closed the stream it had swapped in ("I/O operation on closed file").
"""

from __future__ import annotations

import io
import sys
from collections.abc import Iterator

import pytest
import structlog

from scanner.log_config import configure_console_logging


@pytest.fixture(autouse=True)
def _restore_structlog() -> Iterator[None]:
    saved = structlog.get_config()
    yield
    structlog.configure(**saved)


def test_warnings_go_to_stderr_and_stdout_stays_clean(capsys) -> None:
    configure_console_logging()
    log = structlog.get_logger("log-config-test")
    log.info("routine detail")
    log.warning("something to look at")
    out, err = capsys.readouterr()
    assert out == ""
    assert "something to look at" in err
    assert "routine detail" not in err  # below the warning threshold


def test_logging_follows_stderr_after_the_old_stream_closes(monkeypatch) -> None:
    first = io.StringIO()
    monkeypatch.setattr(sys, "stderr", first)
    configure_console_logging()
    log = structlog.get_logger("log-config-test")
    log.error("first")
    assert "first" in first.getvalue()

    first.close()
    second = io.StringIO()
    monkeypatch.setattr(sys, "stderr", second)
    log.error("second")  # raised ValueError when the stream was bound at configure time
    assert "second" in second.getvalue()
