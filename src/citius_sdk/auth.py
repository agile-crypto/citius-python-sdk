"""Per-RPC bearer-token support."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

import grpc


class TokenProvider(Protocol):
    """Provides the current access token immediately before each RPC."""

    async def token(self) -> str:
        """Return a bearer token, or an empty string to omit authorization."""
        ...


@dataclass(frozen=True, slots=True)
class StaticTokenProvider:
    """Token provider backed by one fixed value."""

    value: str

    async def token(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CallableTokenProvider:
    """Token provider backed by an async callable, refreshed per RPC."""

    supplier: Callable[[], Awaitable[str]]

    async def token(self) -> str:
        return await self.supplier()


async def _with_bearer_metadata(
    provider: TokenProvider,
    client_call_details: grpc.aio.ClientCallDetails,
) -> grpc.aio.ClientCallDetails:
    token = await provider.token()
    metadata = tuple(
        item for item in (client_call_details.metadata or ()) if item[0].lower() != "authorization"
    )
    if token:
        metadata += (("authorization", f"Bearer {token}"),)
    return grpc.aio.ClientCallDetails(
        method=client_call_details.method,
        timeout=client_call_details.timeout,
        metadata=metadata,
        credentials=client_call_details.credentials,
        wait_for_ready=client_call_details.wait_for_ready,
    )


class BearerAuthInterceptor(grpc.aio.UnaryUnaryClientInterceptor):
    """Adds the token provider's latest bearer token to unary RPC metadata."""

    def __init__(self, provider: TokenProvider) -> None:
        self._provider = provider

    async def intercept_unary_unary(
        self,
        continuation: grpc.aio.UnaryUnaryMultiCallable,
        client_call_details: grpc.aio.ClientCallDetails,
        request: object,
    ) -> grpc.aio.UnaryUnaryCall:
        call_details = await _with_bearer_metadata(self._provider, client_call_details)
        return await continuation(call_details, request)


class UnaryStreamBearerInterceptor(grpc.aio.UnaryStreamClientInterceptor):
    """Adds the bearer token to unary-request, streaming-response RPC metadata."""

    def __init__(self, provider: TokenProvider) -> None:
        self._provider = provider

    async def intercept_unary_stream(
        self,
        continuation: grpc.aio.UnaryStreamMultiCallable,
        client_call_details: grpc.aio.ClientCallDetails,
        request: object,
    ) -> grpc.aio.UnaryStreamCall:
        call_details = await _with_bearer_metadata(self._provider, client_call_details)
        return await continuation(call_details, request)


class StreamUnaryBearerInterceptor(grpc.aio.StreamUnaryClientInterceptor):
    """Adds the bearer token to streaming-request, unary-response RPC metadata."""

    def __init__(self, provider: TokenProvider) -> None:
        self._provider = provider

    async def intercept_stream_unary(
        self,
        continuation: grpc.aio.StreamUnaryMultiCallable,
        client_call_details: grpc.aio.ClientCallDetails,
        request_iterator: object,
    ) -> grpc.aio.StreamUnaryCall:
        call_details = await _with_bearer_metadata(self._provider, client_call_details)
        return await continuation(call_details, request_iterator)


class StreamStreamBearerInterceptor(grpc.aio.StreamStreamClientInterceptor):
    """Adds the bearer token to bidirectional streaming RPC metadata."""

    def __init__(self, provider: TokenProvider) -> None:
        self._provider = provider

    async def intercept_stream_stream(
        self,
        continuation: grpc.aio.StreamStreamMultiCallable,
        client_call_details: grpc.aio.ClientCallDetails,
        request_iterator: object,
    ) -> grpc.aio.StreamStreamCall:
        call_details = await _with_bearer_metadata(self._provider, client_call_details)
        return await continuation(call_details, request_iterator)
