from __future__ import annotations

import pytest

from citius_sdk import CitiusError, check_api_compatibility
from citius_sdk import version as version_module


def test_installed_matches_recorded_pin() -> None:
    assert version_module.installed_api_version() == version_module.compatible_api_version()


def test_check_api_compatibility_passes_for_matching_pin() -> None:
    check_api_compatibility()


def test_check_api_compatibility_rejects_drift(monkeypatch) -> None:
    monkeypatch.setattr(version_module, "installed_api_version", lambda: "9.9.9")
    with pytest.raises(CitiusError):
        check_api_compatibility()
