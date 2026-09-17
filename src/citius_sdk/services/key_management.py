"""Key management service client."""

from __future__ import annotations

import grpc
from citius_api.messages.key_management_pb2 import (
    CreateKeyRequest,
    CreateKeyResponse,
    KeyMetadata,
    ReadKeyRequest,
    ReadKeyResponse,
    TransformKeyRequest,
    TransformKeyResponse,
)
from citius_api.services.key_management_service_pb2_grpc import KeyManagementServiceStub

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


def create_key_request(
    name: str,
    *,
    policy: str = "",
    template_id: str = "",
    provider_id: str = "",
) -> CreateKeyRequest:
    """Build a CreateKeyRequest identified by name and an optional template."""
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _raise_if_invalid("create key request", errors)
    return CreateKeyRequest(
        name=name, policy=policy, template_id=template_id, provider_id=provider_id
    )


def read_key_request(name: str, *, version: int | None = None) -> ReadKeyRequest:
    """Build a ReadKeyRequest for a key, optionally pinned to a version."""
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _raise_if_invalid("read key request", errors)
    request = ReadKeyRequest(name=name)
    if version is not None:
        request.version = version
    return request


def transform_key_request(
    name: str,
    *,
    retain_key_bytes: bool = False,
    template_id: str = "",
) -> TransformKeyRequest:
    """Build a TransformKeyRequest to move a key to a new template."""
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _raise_if_invalid("transform key request", errors)
    return TransformKeyRequest(
        name=name, retain_key_bytes=retain_key_bytes, template_id=template_id
    )


class KeyMetadataView:
    """Read-only view over key metadata preserving the underlying message."""

    def __init__(self, inner: KeyMetadata) -> None:
        self._inner = inner

    @property
    def proto(self) -> KeyMetadata:
        return self._inner

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def version(self) -> int:
        return self._inner.version

    @property
    def key_id(self) -> str:
        return self._inner.key_id

    @property
    def template_id(self) -> str:
        return self._inner.template_id

    @property
    def policy(self) -> str:
        return self._inner.policy


class CreateKeyResult:
    """Outcome of a key creation."""

    def __init__(self, inner: CreateKeyResponse) -> None:
        self._inner = inner

    @property
    def success(self) -> bool:
        return self._inner.success

    @property
    def message(self) -> str:
        return self._inner.message

    @property
    def key_metadata(self) -> KeyMetadataView | None:
        return (
            KeyMetadataView(self._inner.key_metadata)
            if self._inner.HasField("key_metadata")
            else None
        )


class ReadKeyResult:
    """Key metadata returned by a read operation."""

    def __init__(self, inner: ReadKeyResponse) -> None:
        self._inner = inner

    @property
    def key_metadata(self) -> KeyMetadataView | None:
        return (
            KeyMetadataView(self._inner.key_metadata)
            if self._inner.HasField("key_metadata")
            else None
        )


class TransformKeyResult:
    """Outcome of a key transformation."""

    def __init__(self, inner: TransformKeyResponse) -> None:
        self._inner = inner

    @property
    def success(self) -> bool:
        return self._inner.success

    @property
    def message(self) -> str:
        return self._inner.message

    @property
    def key_metadata(self) -> KeyMetadataView | None:
        return (
            KeyMetadataView(self._inner.key_metadata)
            if self._inner.HasField("key_metadata")
            else None
        )


class KeyManagementClient:
    """Async client for key lifecycle management."""

    def __init__(
        self,
        channel: grpc.aio.Channel,
        *,
        timeout: float,
        close_channel: bool = False,
    ) -> None:
        self._channel = channel
        self._stub = KeyManagementServiceStub(channel)
        self._timeout = timeout
        self._close_channel = close_channel

    @classmethod
    def connect(
        cls,
        config: ClientConfig,
        *,
        token_provider: TokenProvider | None = None,
    ) -> KeyManagementClient:
        """Create a key management client that owns its configured channel."""
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
    async def create_key(
        self, request: CreateKeyRequest, *, timeout: float | None = None
    ) -> CreateKeyResult:
        response = await self._stub.CreateKey(request, timeout=self._deadline(timeout))
        return CreateKeyResult(response)

    @map_rpc_errors
    async def read_key(
        self, request: ReadKeyRequest, *, timeout: float | None = None
    ) -> ReadKeyResult:
        response = await self._stub.ReadKey(request, timeout=self._deadline(timeout))
        return ReadKeyResult(response)

    @map_rpc_errors
    async def transform_key(
        self, request: TransformKeyRequest, *, timeout: float | None = None
    ) -> TransformKeyResult:
        response = await self._stub.TransformKey(request, timeout=self._deadline(timeout))
        return TransformKeyResult(response)

    async def close(self, grace: float | None = None) -> None:
        """Close the channel when this client created it."""
        if self._close_channel:
            await self._channel.close(grace)

    async def __aenter__(self) -> KeyManagementClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()
