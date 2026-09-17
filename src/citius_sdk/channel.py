"""Shared asynchronous gRPC channel construction."""

from __future__ import annotations

from pathlib import Path

import grpc

from citius_sdk.auth import (
    BearerAuthInterceptor,
    StreamStreamBearerInterceptor,
    StreamUnaryBearerInterceptor,
    TokenProvider,
    UnaryStreamBearerInterceptor,
)
from citius_sdk.config import ClientConfig


def _read(path: Path | str | None) -> bytes | None:
    return Path(path).read_bytes() if path is not None else None


def create_channel(
    config: ClientConfig, token_provider: TokenProvider | None = None
) -> grpc.aio.Channel:
    """Create an async channel, fetching authentication per RPC."""
    interceptors = (
        (
            BearerAuthInterceptor(token_provider),
            UnaryStreamBearerInterceptor(token_provider),
            StreamUnaryBearerInterceptor(token_provider),
            StreamStreamBearerInterceptor(token_provider),
        )
        if token_provider is not None
        else ()
    )
    if not config.tls.enabled:
        return grpc.aio.insecure_channel(
            config.endpoint,
            options=config.channel_options,
            interceptors=interceptors,
        )

    credentials = grpc.ssl_channel_credentials(
        root_certificates=_read(config.tls.ca_cert),
        private_key=_read(config.tls.client_key),
        certificate_chain=_read(config.tls.client_cert),
    )
    return grpc.aio.secure_channel(
        config.endpoint,
        credentials,
        options=config.channel_options,
        interceptors=interceptors,
    )
