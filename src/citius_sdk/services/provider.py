"""Provider service client: the read-only provider catalogue and matching."""

from __future__ import annotations

import grpc
from citius_api.services.provider_service_pb2 import (
    GetProviderInstanceRequest,
    GetProviderRequest,
    ListProviderInstancesRequest,
    ListProviderInstancesResponse,
    ListProvidersRequest,
    ListProvidersResponse,
    MatchProvidersRequest,
    MatchProvidersResponse,
)
from citius_api.services.provider_service_pb2_grpc import ProviderServiceStub
from citius_api.types.implementation_pb2 import ProviderInstance
from citius_api.types.providers_pb2 import ProviderInfo

from citius_sdk.auth import TokenProvider
from citius_sdk.channel import create_channel
from citius_sdk.config import ClientConfig
from citius_sdk.errors import InvalidArgumentError, map_rpc_errors
from citius_sdk.vocabulary import ProviderRequirements


def _requirements_into(request: object, requirements: ProviderRequirements | None) -> None:
    if requirements is not None:
        request.requirements.CopyFrom(requirements.to_proto())  # type: ignore[attr-defined]


class ProviderClient:
    """Async client for provider discovery.

    A provider (``openssl``) is a kind of backend; an instance
    (``openssl-fips``) is one configured backend of that kind, with its own
    implementation properties. Responses are the generated messages.
    """

    def __init__(
        self,
        channel: grpc.aio.Channel,
        *,
        timeout: float,
        close_channel: bool = False,
    ) -> None:
        self._channel = channel
        self._stub = ProviderServiceStub(channel)
        self._timeout = timeout
        self._close_channel = close_channel

    @classmethod
    def connect(
        cls,
        config: ClientConfig,
        *,
        token_provider: TokenProvider | None = None,
    ) -> ProviderClient:
        """Create a provider client that owns its configured channel."""
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
    async def list_providers(
        self,
        *,
        template_id: str = "",
        requirements: ProviderRequirements | None = None,
        page_size: int = 0,
        page_token: str = "",
        timeout: float | None = None,
    ) -> ListProvidersResponse:
        """List providers with an instance serving ``template_id`` under ``requirements``."""
        request = ListProvidersRequest(
            template_id=template_id, page_size=page_size, page_token=page_token
        )
        _requirements_into(request, requirements)
        return await self._stub.ListProviders(request, timeout=self._deadline(timeout))

    @map_rpc_errors
    async def get_provider(self, provider_id: str, *, timeout: float | None = None) -> ProviderInfo:
        if not provider_id:
            raise InvalidArgumentError(grpc.StatusCode.INVALID_ARGUMENT, "provider_id is empty")
        response = await self._stub.GetProvider(
            GetProviderRequest(provider_id=provider_id), timeout=self._deadline(timeout)
        )
        return response.provider

    @map_rpc_errors
    async def list_provider_instances(
        self,
        *,
        provider_id: str = "",
        requirements: ProviderRequirements | None = None,
        page_size: int = 0,
        page_token: str = "",
        timeout: float | None = None,
    ) -> ListProviderInstancesResponse:
        """List instances, each with the implementation properties it reports."""
        request = ListProviderInstancesRequest(
            provider_id=provider_id, page_size=page_size, page_token=page_token
        )
        _requirements_into(request, requirements)
        return await self._stub.ListProviderInstances(request, timeout=self._deadline(timeout))

    @map_rpc_errors
    async def get_provider_instance(
        self, instance_id: str, *, timeout: float | None = None
    ) -> ProviderInstance:
        if not instance_id:
            raise InvalidArgumentError(grpc.StatusCode.INVALID_ARGUMENT, "instance_id is empty")
        response = await self._stub.GetProviderInstance(
            GetProviderInstanceRequest(instance_id=instance_id), timeout=self._deadline(timeout)
        )
        return response.instance

    @map_rpc_errors
    async def match_providers(
        self,
        *,
        template_id: str = "",
        requirements: ProviderRequirements | None = None,
        timeout: float | None = None,
    ) -> MatchProvidersResponse:
        """Rank the instances that can hold a ``template_id`` key under ``requirements``.

        The first match is the instance CreateKey would choose.
        """
        request = MatchProvidersRequest(template_id=template_id)
        _requirements_into(request, requirements)
        return await self._stub.MatchProviders(request, timeout=self._deadline(timeout))

    async def close(self, grace: float | None = None) -> None:
        """Close the channel when this client created it."""
        if self._close_channel:
            await self._channel.close(grace)

    async def __aenter__(self) -> ProviderClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()
