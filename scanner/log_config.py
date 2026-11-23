"""structlog output for the console entry points (CLI, fix loop, MCP server).

stdout carries the payload an agent or script reads (JSON, markdown, MCP
messages), so log events go to stderr, at warning level and above.
"""

from __future__ import annotations

import logging
import sys

import structlog


class _StderrLogger:
    """Print each event to whatever ``sys.stderr`` is at the moment it is logged.

    ``structlog.PrintLoggerFactory(file=sys.stderr)`` keeps the stream object that
    is current when ``structlog.configure`` runs. A host or test harness that
    swaps stderr and later closes the swapped stream (pytest's ``capsys``, an MCP
    stdio wrapper) then makes every later log call raise
    "I/O operation on closed file". Looking the stream up per call avoids that.
    """

    def msg(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    log = debug = info = warn = warning = err = error = critical = exception = failure = fatal = msg


def configure_console_logging(level: int = logging.WARNING) -> None:
    """Send structlog events at ``level`` and above to stderr, keeping stdout for the payload."""
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=lambda *_args: _StderrLogger(),
    )
