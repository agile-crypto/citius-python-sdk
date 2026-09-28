from __future__ import annotations

import grpc
import pytest
import pytest_asyncio
from citius_api.services.provider_service_pb2 import (
    GetProviderInstanceResponse,
    GetProviderResponse,
    ListProviderInstancesResponse,
    ListProvidersResponse,
    MatchProvidersResponse,
)
from citius_api.services.provider_service_pb2_grpc import (
    ProviderServiceServicer,
    add_ProviderServiceServicer_to_server,
)

from citius_sdk import ClientConfig, ProviderRequirements, StaticTokenProvider, TLSConfig
from citius_sdk.errors import InvalidArgumentError, NotFoundError
from citius_sdk.services.provider import ProviderClient


class FakeProviderService(ProviderServiceServicer):
    def __init__(self) -> None:
        self.requests: list[object] = []

    async def ListProviders(self, request, context):  # noqa: N802
        self.requests.append(request)
        response = ListProvidersResponse()
        response.providers.add(provider_id="openssl")
        return response

    async def GetProvider(self, request, context):  # noqa: N802
        if request.provider_id != "openssl":
            await context.abort(grpc.StatusCode.NOT_FOUND, "provider not found")
        response = GetProviderResponse()
        response.provider.provider_id = "openssl"
        return response

    async def ListProviderInstances(self, request, context):  # noqa: N802
        self.requests.append(request)
        response = ListProviderInstancesResponse(next_page_token="1")
        instance = response.instances.add(instance_id="openssl-fips", provider_id="openssl")
        instance.implementation_override.fips_140.certified = True
        return response

    async def GetProviderInstance(self, request, context):  # noqa: N802
        response = GetProviderInstanceResponse()
        response.instance.instance_id = request.instance_id
        return response

    async def MatchProviders(self, request, context):  # noqa: N802
        self.requests.append(request)
        response = MatchProvidersResponse()
        response.matches.add(match_score=2).instance.instance_id = "openssl-fips"
        return response


@pytest_asyncio.fixture
async def provider_endpoint():
    service = FakeProviderService()
    server = grpc.aio.server()
    add_ProviderServiceServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield service, f"127.0.0.1:{port}"
    finally:
        await server.stop(grace=None)


def _connect(endpoint: str) -> ProviderClient:
    return ProviderClient.connect(
        ClientConfig(endpoint=endpoint, tls=TLSConfig(enabled=False)),
        token_provider=StaticTokenProvider("t"),
    )


@pytest.mark.asyncio
async def test_catalogue_reads(provider_endpoint) -> None:
    service, endpoint = provider_endpoint
    fips = ProviderRequirements(fips_140_certified=True)
    async with _connect(endpoint) as client:
        providers = await client.list_providers(template_id="aes-256-gcm", requirements=fips)
        provider = await client.get_provider("openssl")
        instances = await client.list_provider_instances(provider_id="openssl", page_size=1)
        instance = await client.get_provider_instance("openssl-fips")
        matches = await client.match_providers(template_id="aes-256-gcm", requirements=fips)

    assert [p.provider_id for p in providers.providers] == ["openssl"]
    assert provider.provider_id == "openssl"
    assert instances.next_page_token == "1"
    assert instances.instances[0].implementation_override.fips_140.certified is True
    assert instance.instance_id == "openssl-fips"
    assert matches.matches[0].instance.instance_id == "openssl-fips"

    list_providers, list_instances, match = service.requests
    assert list_providers.template_id == "aes-256-gcm"
    assert list_providers.requirements.fips_140_certified is True
    assert list_instances.provider_id == "openssl"
    assert list_instances.page_size == 1
    assert not list_instances.HasField("requirements")
    assert match.requirements.fips_140_certified is True


@pytest.mark.asyncio
async def test_errors(provider_endpoint) -> None:
    _, endpoint = provider_endpoint
    async with _connect(endpoint) as client:
        with pytest.raises(NotFoundError):
            await client.get_provider("hsm")
        with pytest.raises(InvalidArgumentError):
            await client.get_provider("")
        with pytest.raises(InvalidArgumentError):
            await client.get_provider_instance("")
