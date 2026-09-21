from __future__ import annotations

import grpc
import pytest
import pytest_asyncio
from citius_api.messages.key_management_pb2 import (
    CreateKeyResponse,
    ReadKeyResponse,
    TransformKeyResponse,
)
from citius_api.services.key_management_service_pb2_grpc import (
    KeyManagementServiceServicer,
    add_KeyManagementServiceServicer_to_server,
)

from citius_sdk import ClientConfig, StaticTokenProvider, TLSConfig
from citius_sdk.errors import AuthenticationError, InvalidArgumentError, PermissionDeniedError
from citius_sdk.services.key_management import (
    KeyManagementClient,
    create_key_request,
    read_key_request,
    transform_key_request,
)

_DENIED = "demo-restricted-key"


class FakeKeyManagementService(KeyManagementServiceServicer):
    async def _guard(self, context) -> None:
        if dict(context.invocation_metadata()).get("authorization") is None:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "bearer token required")

    async def CreateKey(self, request, context):  # noqa: N802
        await self._guard(context)
        if request.name == _DENIED:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "denied")
        response = CreateKeyResponse(success=True, message="created")
        response.key_metadata.name = request.name
        response.key_metadata.version = 1
        response.key_metadata.template_id = request.template_id
        return response

    async def ReadKey(self, request, context):  # noqa: N802
        await self._guard(context)
        response = ReadKeyResponse()
        response.key_metadata.name = request.name
        response.key_metadata.version = request.version or 1
        return response

    async def TransformKey(self, request, context):  # noqa: N802
        await self._guard(context)
        response = TransformKeyResponse(success=True, message="transformed")
        response.key_metadata.name = request.name
        response.key_metadata.version = 2
        response.key_metadata.template_id = request.template_id
        return response


@pytest_asyncio.fixture
async def key_endpoint():
    server = grpc.aio.server()
    add_KeyManagementServiceServicer_to_server(FakeKeyManagementService(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield f"127.0.0.1:{port}"
    finally:
        await server.stop(grace=None)


def _config(endpoint: str) -> ClientConfig:
    return ClientConfig(endpoint=endpoint, tls=TLSConfig(enabled=False))


@pytest.mark.asyncio
async def test_create_read_transform_key(key_endpoint) -> None:
    async with KeyManagementClient.connect(
        _config(key_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        created = await client.create_key(create_key_request("demo-key", template_id="tmpl-1"))
        assert created.success is True
        assert created.key_metadata is not None
        assert created.key_metadata.name == "demo-key"
        assert created.key_metadata.version == 1

        read = await client.read_key(read_key_request("demo-key"))
        assert read.key_metadata is not None
        assert read.key_metadata.version == 1

        transformed = await client.transform_key(
            transform_key_request("demo-key", template_id="tmpl-2", retain_key_bytes=True)
        )
        assert transformed.key_metadata is not None
        assert transformed.key_metadata.version == 2
        assert transformed.key_metadata.template_id == "tmpl-2"


@pytest.mark.asyncio
async def test_missing_token_raises_authentication_error(key_endpoint) -> None:
    async with KeyManagementClient.connect(_config(key_endpoint)) as client:
        with pytest.raises(AuthenticationError):
            await client.create_key(create_key_request("demo-key", template_id="tmpl-1"))


@pytest.mark.asyncio
async def test_denied_key_raises_permission_denied(key_endpoint) -> None:
    async with KeyManagementClient.connect(
        _config(key_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        with pytest.raises(PermissionDeniedError):
            await client.create_key(create_key_request(_DENIED, template_id="tmpl-1"))


def test_create_key_request_requires_name() -> None:
    with pytest.raises(InvalidArgumentError) as raised:
        create_key_request("", template_id="tmpl-1")
    assert "name is empty" in str(raised.value)
