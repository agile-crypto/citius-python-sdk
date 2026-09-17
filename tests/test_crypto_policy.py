from __future__ import annotations

import grpc
import pytest
import pytest_asyncio
from citius_api.messages.policy_pb2 import (
    CreateCryptoPolicyResponse,
    ReadCryptoPolicyResponse,
    UpdateCryptoPolicyResponse,
)
from citius_api.services.crypto_policy_service_pb2_grpc import (
    CryptoPolicyServiceServicer,
    add_CryptoPolicyServiceServicer_to_server,
)

from citius_sdk import ClientConfig, StaticTokenProvider, TLSConfig
from citius_sdk.errors import AuthenticationError, InvalidArgumentError, PermissionDeniedError
from citius_sdk.services.crypto_policy import (
    CryptoPolicyClient,
    create_policy_request,
    read_policy_request,
    update_policy_request,
)

_DENIED = "demo-restricted-policy"


class FakePolicyService(CryptoPolicyServiceServicer):
    def __init__(self) -> None:
        self.store: dict[str, tuple[str, str, int]] = {}

    async def _guard(self, context) -> None:
        if dict(context.invocation_metadata()).get("authorization") is None:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "bearer token required")

    async def CreateCryptoPolicy(self, request, context):  # noqa: N802
        await self._guard(context)
        if request.name == _DENIED:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "denied")
        self.store[request.name] = (request.policy_document, request.format, 1)
        return CreateCryptoPolicyResponse(success=True, message="created", version=1)

    async def ReadCryptoPolicy(self, request, context):  # noqa: N802
        await self._guard(context)
        document, fmt, version = self.store[request.name]
        return ReadCryptoPolicyResponse(
            name=request.name, policy_document=document, format=fmt, version=version
        )

    async def UpdateCryptoPolicy(self, request, context):  # noqa: N802
        await self._guard(context)
        self.store[request.name] = (request.policy_document, request.format, 2)
        return UpdateCryptoPolicyResponse(success=True, message="updated", version=2)


@pytest_asyncio.fixture
async def policy_endpoint():
    server = grpc.aio.server()
    add_CryptoPolicyServiceServicer_to_server(FakePolicyService(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield f"127.0.0.1:{port}"
    finally:
        await server.stop(grace=None)


def _config(endpoint: str) -> ClientConfig:
    return ClientConfig(endpoint=endpoint, tls=TLSConfig(enabled=False))


@pytest.mark.asyncio
async def test_create_read_update_policy(policy_endpoint) -> None:
    async with CryptoPolicyClient.connect(
        _config(policy_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        created = await client.create_policy(
            create_policy_request("demo-policy", "document", "yaml")
        )
        assert created.success is True
        assert created.version == 1

        read = await client.read_policy(read_policy_request("demo-policy"))
        assert read.policy_document == "document"
        assert read.format == "yaml"

        updated = await client.update_policy(
            update_policy_request("demo-policy", "document2", "yaml", expected_version=1)
        )
        assert updated.version == 2


@pytest.mark.asyncio
async def test_missing_token_raises_authentication_error(policy_endpoint) -> None:
    async with CryptoPolicyClient.connect(_config(policy_endpoint)) as client:
        with pytest.raises(AuthenticationError):
            await client.create_policy(create_policy_request("demo-policy", "d", "yaml"))


@pytest.mark.asyncio
async def test_denied_policy_raises_permission_denied(policy_endpoint) -> None:
    async with CryptoPolicyClient.connect(
        _config(policy_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        with pytest.raises(PermissionDeniedError):
            await client.create_policy(create_policy_request(_DENIED, "d", "yaml"))


def test_create_policy_request_reports_all_errors() -> None:
    with pytest.raises(InvalidArgumentError) as raised:
        create_policy_request("", "", "")
    message = str(raised.value)
    assert "name is empty" in message
    assert "policy document is empty" in message
    assert "format is empty" in message
