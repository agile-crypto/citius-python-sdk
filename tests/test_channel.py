from __future__ import annotations

import pytest

from citius_sdk import ClientConfig, TLSConfig
from citius_sdk.channel import create_channel


def test_create_channel_rejects_ca_file_without_pem(tmp_path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"not a certificate")
    config = ClientConfig(endpoint="citius.example:443", tls=TLSConfig(ca_cert=ca))

    with pytest.raises(ValueError, match="no PEM certificate"):
        create_channel(config)


def test_create_channel_rejects_missing_ca_file(tmp_path) -> None:
    config = ClientConfig(
        endpoint="citius.example:443",
        tls=TLSConfig(ca_cert=tmp_path / "absent.pem"),
    )

    with pytest.raises(FileNotFoundError):
        create_channel(config)


def test_create_channel_accepts_pem_ca(tmp_path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n")
    config = ClientConfig(endpoint="citius.example:443", tls=TLSConfig(ca_cert=ca))

    channel = create_channel(config)
    assert channel is not None


def test_create_insecure_channel_without_token_provider() -> None:
    config = ClientConfig(endpoint="localhost:50051", tls=TLSConfig(enabled=False))
    channel = create_channel(config)
    assert channel is not None
