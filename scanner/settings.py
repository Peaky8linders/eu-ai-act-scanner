"""User-configurable settings for Antifragile Harness.

Two orthogonal behaviour layers, resolved with precedence
**env var > project file > user file > built-in default**:

* ``mode`` — how much the plugin leans on *your own Claude Code*:
    * ``deterministic`` (default) — pure static analysis. No LLM, no network,
      no telemetry. The historical behaviour.
    * ``assisted`` — opt in to using **your own Claude Code power**. The slash
      commands drive the *host* Claude Code session (the one running the
      command — no API key, no separate wrapper) to: run a semantic pass over
      the deterministic findings, answer follow-up questions from the bundled
      knowledge base (``/ai-act-ask``), and — when ``auto_apply`` is on — apply
      remediations with its own edit tools instead of only proposing them.
* ``auto_apply`` — in ``assisted`` mode, let the fix flow apply edits
  automatically rather than proposing-then-waiting. Off by default so a scan is
  never destructive without an explicit opt-in.

Semantic depth outside Claude Code comes from the **MCP server**
(``antifragile-scan-mcp``): any MCP-capable agent calls the same deterministic
engine over the Model Context Protocol using its own model subscription — no
API key and no local wrapper required. ``assisted`` mode inside Claude Code
simply means the host session (your existing subscription) narrates and
remediates over the deterministic baseline.

Config file: ``.antifragile-harness.toml`` at the project root (checked in or
git-ignored, your call), with an optional user-level fallback at
``$XDG_CONFIG_HOME/antifragile-harness.toml`` (``~/.config/...`` when unset). Both
use a ``[scanner]`` table. Files and environment variables saved under the
pre-rename names (``.eu-ai-act-scanner.toml``, ``EU_AI_ACT_SCANNER_*``) are
still read when the new ones are absent, so existing settings keep working.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Mode = Literal["deterministic", "assisted"]

_VALID_MODES: tuple[str, ...] = ("deterministic", "assisted")
PROJECT_CONFIG_NAME = ".antifragile-harness.toml"
USER_CONFIG_NAME = "antifragile-harness.toml"

_ENV_MODE = "ANTIFRAGILE_HARNESS_MODE"
_ENV_AUTO_APPLY = "ANTIFRAGILE_HARNESS_AUTO_APPLY"

# Pre-rename names, read only when the new file or variable is absent.
LEGACY_PROJECT_CONFIG_NAME = ".eu-ai-act-scanner.toml"
LEGACY_USER_CONFIG_NAME = "eu-ai-act-scanner.toml"
_LEGACY_ENV = {
    _ENV_MODE: "EU_AI_ACT_SCANNER_MODE",
    _ENV_AUTO_APPLY: "EU_AI_ACT_SCANNER_AUTO_APPLY",
}


@dataclass(frozen=True)
class Settings:
    """Resolved scanner settings.

    ``source`` records the highest-precedence layer that set any value
    (``env`` / ``project-config`` / ``user-config`` / ``default``) so the
    ``settings`` command can tell the user where their config came from.
    """

    mode: Mode = "deterministic"
    auto_apply: bool = False
    source: str = "default"

    @property
    def assisted(self) -> bool:
        return self.mode == "assisted"

    def to_dict(self) -> dict:
        """Diagnostic view — safe to print / log (no secrets)."""
        return {
            "mode": self.mode,
            "auto_apply": self.auto_apply,
            "source": self.source,
        }


def _prefer_current(current: Path, legacy: Path) -> Path:
    """The current-name file, unless only the pre-rename file exists."""
    return legacy if legacy.exists() and not current.exists() else current


def _user_config_path() -> Path:
    base = os.getenv("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return _prefer_current(root / USER_CONFIG_NAME, root / LEGACY_USER_CONFIG_NAME)


def _project_config_path(root: Path) -> Path:
    return _prefer_current(root / PROJECT_CONFIG_NAME, root / LEGACY_PROJECT_CONFIG_NAME)


def _env(name: str) -> str | None:
    """Read an override variable, falling back to its pre-rename name."""
    return os.getenv(name) or os.getenv(_LEGACY_ENV[name])


def _coerce_mode(value: object) -> Mode | None:
    if isinstance(value, str) and value.strip().lower() in _VALID_MODES:
        return value.strip().lower()  # type: ignore[return-value]
    return None


def _coerce_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1", "yes", "on"):
            return True
        if low in ("false", "0", "no", "off"):
            return False
    return None


def _read_toml(path: Path) -> dict:
    """Read the ``[scanner]`` table from a TOML file; ``{}`` on any problem."""
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    section = data.get("scanner")
    if isinstance(section, dict):
        return section
    return data if isinstance(data, dict) else {}


def load_settings(project_root: str | Path | None = None) -> Settings:
    """Resolve settings from env > project file > user file > default."""
    root = Path(project_root) if project_root else Path.cwd()

    # Lowest precedence first; later layers override earlier ones.
    layers: list[tuple[str, dict]] = [("default", {})]
    user = _read_toml(_user_config_path())
    if user:
        layers.append(("user-config", user))
    proj = _read_toml(_project_config_path(root))
    if proj:
        layers.append(("project-config", proj))
    env: dict = {}
    if _env(_ENV_MODE):
        env["mode"] = _env(_ENV_MODE)
    if _env(_ENV_AUTO_APPLY):
        env["auto_apply"] = _env(_ENV_AUTO_APPLY)
    if env:
        layers.append(("env", env))

    mode: Mode = "deterministic"
    auto_apply = False
    source = "default"
    for name, layer in layers:
        coerced_mode = _coerce_mode(layer.get("mode"))
        if coerced_mode is not None:
            mode = coerced_mode
            source = name
        coerced_auto = _coerce_bool(layer.get("auto_apply"))
        if coerced_auto is not None:
            auto_apply = coerced_auto
            source = name
    return Settings(mode=mode, auto_apply=auto_apply, source=source)


def save_settings(
    *,
    mode: str | None = None,
    auto_apply: bool | str | None = None,
    project_root: str | Path | None = None,
) -> tuple[Path, Settings]:
    """Persist ``mode`` / ``auto_apply`` to the project ``.antifragile-harness.toml``.

    Only the provided fields change; the rest keep their current resolved value.
    Returns ``(path, new_settings)``. Raises ``ValueError`` on an invalid mode
    so the caller can surface a clean error.
    """
    root = Path(project_root) if project_root else Path.cwd()
    current = load_settings(root)

    new_mode: Mode = current.mode
    if mode is not None:
        coerced = _coerce_mode(mode)
        if coerced is None:
            raise ValueError(f"invalid mode {mode!r}; expected one of {_VALID_MODES}")
        new_mode = coerced

    new_auto = current.auto_apply
    if auto_apply is not None:
        coerced_auto = _coerce_bool(auto_apply)
        if coerced_auto is None:
            raise ValueError(f"invalid auto_apply {auto_apply!r}; expected a boolean")
        new_auto = coerced_auto

    path = root / PROJECT_CONFIG_NAME
    body = (
        "# Antifragile Harness settings — manage via `/ai-act-settings` or\n"
        "# `antifragile-scan --set mode=assisted`.\n"
        "[scanner]\n"
        f'mode = "{new_mode}"\n'
        f"auto_apply = {'true' if new_auto else 'false'}\n"
    )
    path.write_text(body, encoding="utf-8")
    return path, Settings(mode=new_mode, auto_apply=new_auto, source="project-config")
