"""Algorithm discovery service client."""

from __future__ import annotations

import grpc
from citius_api.services.discovery_service_pb2 import (
    ListTemplatesRequest,
    ListTemplatesResponse,
)
from citius_api.services.discovery_service_pb2_grpc import AlgorithmDiscoveryServiceStub

from citius_sdk.auth import TokenProvider
from citius_sdk.channel import create_channel
from citius_sdk.config import ClientConfig


class DiscoveryClient:
    """Async client for read-only algorithm and template discovery."""

    def __init__(
        self,
        channel: grpc.aio.Channel,
        *,
        timeout: float,
        close_channel: bool = False,
    ) -> None:
        self._channel = channel
        self._stub = AlgorithmDiscoveryServiceStub(channel)
        self._timeout = timeout
        self._close_channel = close_channel

    @classmethod
    def connect(
        cls,
        config: ClientConfig,
        *,
        token_provider: TokenProvider | None = None,
    ) -> DiscoveryClient:
        """Create a discovery client that owns its configured channel."""
        return cls(
            create_channel(config, token_provider),
            timeout=config.timeout,
            close_channel=True,
        )

    async def list_templates(
        self,
        request: ListTemplatesRequest | None = None,
        *,
        timeout: float | None = None,
    ) -> ListTemplatesResponse:
        """List templates using the generated request and response contract."""
        deadline = self._timeout if timeout is None else timeout
        if deadline <= 0:
            raise ValueError("timeout must be greater than zero")
        return await self._stub.ListTemplates(request or ListTemplatesRequest(), timeout=deadline)

    async def close(self, grace: float | None = None) -> None:
        """Close the channel when this client created it."""
        if self._close_channel:
            await self._channel.close(grace)

    async def __aenter__(self) -> DiscoveryClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()
