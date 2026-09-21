"""Crypto policy service client."""

from __future__ import annotations

import grpc
from citius_api.messages.policy_pb2 import (
    CreateCryptoPolicyRequest,
    CreateCryptoPolicyResponse,
    ReadCryptoPolicyRequest,
    ReadCryptoPolicyResponse,
    UpdateCryptoPolicyRequest,
    UpdateCryptoPolicyResponse,
)
from citius_api.services.crypto_policy_service_pb2_grpc import CryptoPolicyServiceStub

from citius_sdk.auth import TokenProvider
from citius_sdk.channel import create_channel
from citius_sdk.config import ClientConfig
from citius_sdk.errors import InvalidArgumentError, map_rpc_errors


def _require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _raise_if_invalid(request_type: str, errors: list[str]) -> None:
    if errors:
        raise InvalidArgumentError(
            grpc.StatusCode.INVALID_ARGUMENT,
            f"invalid {request_type}: {'; '.join(errors)}",
        )


def create_policy_request(
    name: str, policy_document: str, policy_format: str
) -> CreateCryptoPolicyRequest:
    """Build a CreateCryptoPolicyRequest."""
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _require(errors, bool(policy_document), "policy document is empty")
    _require(errors, bool(policy_format), "format is empty")
    _raise_if_invalid("create policy request", errors)
    return CreateCryptoPolicyRequest(
        name=name, policy_document=policy_document, format=policy_format
    )


def read_policy_request(name: str) -> ReadCryptoPolicyRequest:
    """Build a ReadCryptoPolicyRequest."""
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _raise_if_invalid("read policy request", errors)
    return ReadCryptoPolicyRequest(name=name)


def update_policy_request(
    name: str,
    policy_document: str,
    policy_format: str,
    *,
    expected_version: int | None = None,
) -> UpdateCryptoPolicyRequest:
    """Build an UpdateCryptoPolicyRequest with an optional optimistic version."""
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _require(errors, bool(policy_document), "policy document is empty")
    _require(errors, bool(policy_format), "format is empty")
    _raise_if_invalid("update policy request", errors)
    request = UpdateCryptoPolicyRequest(
        name=name, policy_document=policy_document, format=policy_format
    )
    if expected_version is not None:
        request.expected_version = expected_version
    return request


class CreatePolicyResult:
    """Outcome of a policy creation."""

    def __init__(self, inner: CreateCryptoPolicyResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> CreateCryptoPolicyResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def success(self) -> bool:
        return self._inner.success

    @property
    def message(self) -> str:
        return self._inner.message

    @property
    def version(self) -> int:
        return self._inner.version


class ReadPolicyResult:
    """A stored crypto policy document and its metadata."""

    def __init__(self, inner: ReadCryptoPolicyResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> ReadCryptoPolicyResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def policy_document(self) -> str:
        return self._inner.policy_document

    @property
    def format(self) -> str:
        return self._inner.format

    @property
    def version(self) -> int:
        return self._inner.version


class UpdatePolicyResult:
    """Outcome of a policy update."""

    def __init__(self, inner: UpdateCryptoPolicyResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> UpdateCryptoPolicyResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def success(self) -> bool:
        return self._inner.success

    @property
    def message(self) -> str:
        return self._inner.message

    @property
    def version(self) -> int:
        return self._inner.version


class CryptoPolicyClient:
    """Async client for crypto policy management."""

    def __init__(
        self,
        channel: grpc.aio.Channel,
        *,
        timeout: float,
        close_channel: bool = False,
    ) -> None:
        self._channel = channel
        self._stub = CryptoPolicyServiceStub(channel)
        self._timeout = timeout
        self._close_channel = close_channel

    @classmethod
    def connect(
        cls,
        config: ClientConfig,
        *,
        token_provider: TokenProvider | None = None,
    ) -> CryptoPolicyClient:
        """Create a crypto policy client that owns its configured channel."""
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
    async def create_policy(
        self, request: CreateCryptoPolicyRequest, *, timeout: float | None = None
    ) -> CreatePolicyResult:
        response = await self._stub.CreateCryptoPolicy(request, timeout=self._deadline(timeout))
        return CreatePolicyResult(response)

    @map_rpc_errors
    async def read_policy(
        self, request: ReadCryptoPolicyRequest, *, timeout: float | None = None
    ) -> ReadPolicyResult:
        response = await self._stub.ReadCryptoPolicy(request, timeout=self._deadline(timeout))
        return ReadPolicyResult(response)

    @map_rpc_errors
    async def update_policy(
        self, request: UpdateCryptoPolicyRequest, *, timeout: float | None = None
    ) -> UpdatePolicyResult:
        response = await self._stub.UpdateCryptoPolicy(request, timeout=self._deadline(timeout))
        return UpdatePolicyResult(response)

    async def close(self, grace: float | None = None) -> None:
        """Close the channel when this client created it."""
        if self._close_channel:
            await self._channel.close(grace)

    async def __aenter__(self) -> CryptoPolicyClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()
