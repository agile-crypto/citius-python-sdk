"""Compatibility check against the generated Citius API distribution."""

from __future__ import annotations

import importlib.metadata

import grpc

from citius_sdk.errors import CitiusError

_API_DISTRIBUTION = "citius-api-python"
_COMPATIBLE_API_VERSION = "0.0.0.dev0+717efdb1cfbc"


def installed_api_version() -> str:
    """Return the installed citius-api-python distribution version."""
    return importlib.metadata.version(_API_DISTRIBUTION)


def compatible_api_version() -> str:
    """Return the API version this SDK release was built and tested against."""
    return _COMPATIBLE_API_VERSION


def check_api_compatibility() -> None:
    """Raise when the installed generated API drifts from the recorded pin."""
    installed = installed_api_version()
    if installed != _COMPATIBLE_API_VERSION:
        raise CitiusError(
            grpc.StatusCode.FAILED_PRECONDITION,
            f"citius-api-python {installed} is incompatible with {_COMPATIBLE_API_VERSION}",
        )
