"""Per-RPC bearer-token support."""

from __future__ import annotations

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
        token = await self._provider.token()
        metadata = tuple(
            item
            for item in (client_call_details.metadata or ())
            if item[0].lower() != "authorization"
        )
        if token:
            metadata += (("authorization", f"Bearer {token}"),)

        call_details = grpc.aio.ClientCallDetails(
            method=client_call_details.method,
            timeout=client_call_details.timeout,
            metadata=metadata,
            credentials=client_call_details.credentials,
            wait_for_ready=client_call_details.wait_for_ready,
        )
        return await continuation(call_details, request)
