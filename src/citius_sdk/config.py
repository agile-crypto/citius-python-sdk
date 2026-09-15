"""Connection configuration for Citius service clients."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class TLSConfig:
    """TLS and optional mutual-TLS file configuration."""

    enabled: bool = True
    ca_cert: Path | str | None = None
    client_cert: Path | str | None = None
    client_key: Path | str | None = None
    server_name: str | None = None

    def __post_init__(self) -> None:
        if (self.client_cert is None) != (self.client_key is None):
            raise ValueError("client_cert and client_key must be configured together")
        if not self.enabled and any(
            value is not None
            for value in (self.ca_cert, self.client_cert, self.client_key, self.server_name)
        ):
            raise ValueError("TLS options cannot be set when TLS is disabled")


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Resolved connection settings for one Citius service endpoint."""

    endpoint: str
    tls: TLSConfig = field(default_factory=TLSConfig)
    timeout: float = 10.0
    max_send_message_length: int = 16 * 1024 * 1024
    max_receive_message_length: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        if not self.endpoint or self.endpoint != self.endpoint.strip():
            raise ValueError("endpoint must be a non-empty value without surrounding whitespace")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if self.max_send_message_length <= 0 or self.max_receive_message_length <= 0:
            raise ValueError("message-size limits must be greater than zero")

    @property
    def channel_options(self) -> tuple[tuple[str, int | str], ...]:
        options: list[tuple[str, int | str]] = [
            ("grpc.max_send_message_length", self.max_send_message_length),
            ("grpc.max_receive_message_length", self.max_receive_message_length),
        ]
        if self.tls.server_name:
            options.append(("grpc.ssl_target_name_override", self.tls.server_name))
        return tuple(options)
