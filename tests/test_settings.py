"""Tests for the scanner settings layer (scanner.settings).

Settings gate the ``assisted`` / ``auto_apply`` behaviour — a wrong default
here would either silently disable the deterministic guarantee or silently
enable destructive auto-apply, so the precedence (env > project > user >
default) and the safe defaults are the load-bearing contract.
"""

from __future__ import annotations

import pytest

from scanner.settings import PROJECT_CONFIG_NAME, load_settings, save_settings


@pytest.fixture(autouse=True)
def _isolate_config(monkeypatch, tmp_path):
    # Point the user-config fallback at an empty dir so a real ~/.config file
    # never leaks into the test, and clear the env overrides.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-empty"))
    monkeypatch.delenv("EU_AI_ACT_SCANNER_MODE", raising=False)
    monkeypatch.delenv("EU_AI_ACT_SCANNER_AUTO_APPLY", raising=False)


def test_safe_defaults(tmp_path):
    s = load_settings(project_root=tmp_path)
    assert s.mode == "deterministic"
    assert s.auto_apply is False
    assert s.assisted is False
    assert s.source == "default"


def test_save_and_reload_from_project(tmp_path):
    path, saved = save_settings(mode="assisted", auto_apply=True, project_root=tmp_path)
    assert path.name == PROJECT_CONFIG_NAME
    assert saved.mode == "assisted"
    assert saved.auto_apply is True

    reloaded = load_settings(project_root=tmp_path)
    assert reloaded.mode == "assisted"
    assert reloaded.auto_apply is True
    assert reloaded.source == "project-config"


def test_env_overrides_project_file(tmp_path, monkeypatch):
    save_settings(mode="deterministic", auto_apply=False, project_root=tmp_path)
    monkeypatch.setenv("EU_AI_ACT_SCANNER_MODE", "assisted")
    s = load_settings(project_root=tmp_path)
    assert s.mode == "assisted"
    assert s.source == "env"


def test_invalid_mode_rejected(tmp_path):
    with pytest.raises(ValueError):
        save_settings(mode="bogus", project_root=tmp_path)


def test_to_dict_surfaces_no_secret(tmp_path):
    d = load_settings(project_root=tmp_path).to_dict()
    assert "mode" in d and "llm_bridge" in d
    # The bridge config surfaces only the key SOURCE, never the value.
    assert "api_key" not in d["llm_bridge"]
    assert d["llm_bridge"]["api_key_source"] in ("env", "default")
