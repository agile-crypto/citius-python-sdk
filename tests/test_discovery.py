from __future__ import annotations

import grpc
import pytest
import pytest_asyncio
from citius_api.services.discovery_service_pb2 import (
    GetTemplateResponse,
    ListScopesResponse,
    ListTemplatesRequest,
    ListTemplatesResponse,
)
from citius_api.services.discovery_service_pb2_grpc import (
    AlgorithmDiscoveryServiceServicer,
    add_AlgorithmDiscoveryServiceServicer_to_server,
)

from citius_sdk import ClientConfig, StaticTokenProvider, TLSConfig
from citius_sdk.errors import AuthenticationError, InvalidArgumentError, NotFoundError
from citius_sdk.services.discovery import DiscoveryClient


class RotatingTokenProvider:
    def __init__(self) -> None:
        self.calls = 0

    async def token(self) -> str:
        self.calls += 1
        return f"token-{self.calls}"


class DiscoveryService(AlgorithmDiscoveryServiceServicer):
    def __init__(self) -> None:
        self.authorization: list[str | None] = []

    async def ListTemplates(self, request, context):  # noqa: N802
        metadata = dict(context.invocation_metadata())
        authorization = metadata.get("authorization")
        self.authorization.append(authorization)
        if authorization is None:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "bearer token required")
        return ListTemplatesResponse(next_page_token=str(request.page_size))

    async def GetTemplate(self, request, context):  # noqa: N802
        if request.template_id != "aes-256-gcm":
            await context.abort(grpc.StatusCode.NOT_FOUND, "template not found")
        response = GetTemplateResponse()
        response.template.template_id = request.template_id
        return response

    async def ListScopes(self, request, context):  # noqa: N802
        response = ListScopesResponse()
        response.scopes.add(name="aead_standard")
        return response


@pytest_asyncio.fixture
async def discovery_server():
    service = DiscoveryService()
    server = grpc.aio.server()
    add_AlgorithmDiscoveryServiceServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield service, f"127.0.0.1:{port}"
    finally:
        await server.stop(grace=None)


@pytest.mark.asyncio
async def test_list_templates_fetches_and_attaches_token_for_each_rpc(discovery_server) -> None:
    service, endpoint = discovery_server
    provider = RotatingTokenProvider()
    config = ClientConfig(endpoint=endpoint, tls=TLSConfig(enabled=False))

    async with DiscoveryClient.connect(config, token_provider=provider) as client:
        first = await client.list_templates(ListTemplatesRequest(page_size=10))
        second = await client.list_templates(ListTemplatesRequest(page_size=20))

    assert first.next_page_token == "10"
    assert second.next_page_token == "20"
    assert provider.calls == 2
    assert service.authorization == ["Bearer token-1", "Bearer token-2"]


@pytest.mark.asyncio
async def test_list_templates_without_provider_is_unauthenticated(discovery_server) -> None:
    _, endpoint = discovery_server
    config = ClientConfig(endpoint=endpoint, tls=TLSConfig(enabled=False))

    async with DiscoveryClient.connect(config) as client:
        with pytest.raises(AuthenticationError):
            await client.list_templates()


@pytest.mark.asyncio
async def test_get_template_and_list_scopes(discovery_server) -> None:
    _, endpoint = discovery_server
    config = ClientConfig(endpoint=endpoint, tls=TLSConfig(enabled=False))

    async with DiscoveryClient.connect(config, token_provider=StaticTokenProvider("t")) as client:
        template = await client.get_template("aes-256-gcm")
        scopes = await client.list_scopes()
        with pytest.raises(NotFoundError):
            await client.get_template("rot13")
        with pytest.raises(InvalidArgumentError):
            await client.get_template("")

    assert template.template_id == "aes-256-gcm"
    assert [s.name for s in scopes.scopes] == ["aead_standard"]
