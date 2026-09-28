"""Algorithm discovery service client."""

from __future__ import annotations

import grpc
from citius_api.services.discovery_service_pb2 import (
    GetTemplateRequest,
    ListScopesRequest,
    ListScopesResponse,
    ListTemplatesRequest,
    ListTemplatesResponse,
)
from citius_api.services.discovery_service_pb2_grpc import AlgorithmDiscoveryServiceStub
from citius_api.types.templates_pb2 import TemplateInfo

from citius_sdk.auth import TokenProvider
from citius_sdk.channel import create_channel
from citius_sdk.config import ClientConfig
from citius_sdk.errors import InvalidArgumentError, map_rpc_errors


class DiscoveryClient:
    """Async client for read-only algorithm and template discovery.

    Responses are the generated messages, unwrapped: the catalogue is data to
    display or filter, not state to act on.
    """

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

    def _deadline(self, timeout: float | None) -> float:
        deadline = self._timeout if timeout is None else timeout
        if deadline <= 0:
            raise ValueError("timeout must be greater than zero")
        return deadline

    @map_rpc_errors
    async def list_templates(
        self,
        request: ListTemplatesRequest | None = None,
        *,
        timeout: float | None = None,
    ) -> ListTemplatesResponse:
        """List templates, ordered by ID, narrowed by the request's filters."""
        return await self._stub.ListTemplates(
            request or ListTemplatesRequest(), timeout=self._deadline(timeout)
        )

    @map_rpc_errors
    async def get_template(self, template_id: str, *, timeout: float | None = None) -> TemplateInfo:
        """Return one template's catalogue entry."""
        if not template_id:
            raise InvalidArgumentError(grpc.StatusCode.INVALID_ARGUMENT, "template_id is empty")
        response = await self._stub.GetTemplate(
            GetTemplateRequest(template_id=template_id), timeout=self._deadline(timeout)
        )
        return response.template

    @map_rpc_errors
    async def list_scopes(self, *, timeout: float | None = None) -> ListScopesResponse:
        """List the scopes the catalogue's templates offer, in enum order."""
        return await self._stub.ListScopes(ListScopesRequest(), timeout=self._deadline(timeout))

    async def close(self, grace: float | None = None) -> None:
        """Close the channel when this client created it."""
        if self._close_channel:
            await self._channel.close(grace)

    async def __aenter__(self) -> DiscoveryClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()
