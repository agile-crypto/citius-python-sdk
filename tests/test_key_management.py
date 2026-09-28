from __future__ import annotations

import grpc
import pytest
import pytest_asyncio
from citius_api.messages.key_management_pb2 import (
    CreateKeyResponse,
    KeyMetadata,
    MigrateKeyResponse,
    MigrationStrategy,
    ReadKeyResponse,
    TransformKeyResponse,
)
from citius_api.services.key_management_service_pb2_grpc import (
    KeyManagementServiceServicer,
    add_KeyManagementServiceServicer_to_server,
)
from citius_api.types.common_pb2 import KeyLifecycleState, KeyOrigin

from citius_sdk import ClientConfig, StaticTokenProvider, TLSConfig
from citius_sdk.errors import AuthenticationError, InvalidArgumentError, PermissionDeniedError
from citius_sdk.services.key_management import (
    KeyManagementClient,
    KeyMetadataView,
    create_key_request,
    migrate_key_request,
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

    async def MigrateKey(self, request, context):  # noqa: N802
        await self._guard(context)
        response = MigrateKeyResponse(success=True, message="migrated")
        response.key_metadata.name = request.name
        response.key_metadata.version = 2
        target = request.target_instance_id or request.provider_target.provider_id
        response.key_metadata.provider = target
        response.result.strategy_used = request.strategy
        response.result.key_bytes_preserved = (
            request.strategy == MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH
        )
        response.result.source_instance_id = "software"
        response.result.target_instance_id = response.key_metadata.provider
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


def test_key_metadata_view_exposes_placement_and_provenance() -> None:
    md = KeyMetadata(
        name="k",
        provider="openssl",
        extractable=True,
        lifecycle_state=KeyLifecycleState.KEY_LIFECYCLE_STATE_ACTIVE,
        origin=KeyOrigin.KEY_ORIGIN_GENERATED,
    )
    view = KeyMetadataView(md)
    assert view.provider == "openssl"
    assert view.extractable is True
    assert view.lifecycle_state == KeyLifecycleState.KEY_LIFECYCLE_STATE_ACTIVE
    assert view.origin == KeyOrigin.KEY_ORIGIN_GENERATED


@pytest.mark.asyncio
async def test_migrate_key(key_endpoint) -> None:
    async with KeyManagementClient.connect(
        _config(key_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        migrated = await client.migrate_key(
            migrate_key_request(
                "demo-key",
                strategy=MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH,
                target_instance_id="openssl",
            )
        )
    assert migrated.success is True
    assert migrated.key_bytes_preserved is True
    assert migrated.source_instance_id == "software"
    assert migrated.target_instance_id == "openssl"
    assert migrated.key_metadata is not None
    assert migrated.key_metadata.version == 2


def test_migrate_key_request_targets() -> None:
    by_type = migrate_key_request(
        "k",
        strategy=MigrationStrategy.MIGRATION_STRATEGY_REKEY_AND_ARCHIVE,
        target_provider_id="openssl",
    )
    assert by_type.WhichOneof("target") == "provider_target"
    assert by_type.provider_target.provider_id == "openssl"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"target_instance_id": "openssl"}, "strategy is unspecified"),
        ({"strategy": MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH}, "exactly one of"),
        (
            {
                "strategy": MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH,
                "target_instance_id": "openssl",
                "target_provider_id": "openssl",
            },
            "exactly one of",
        ),
    ],
)
def test_migrate_key_request_validation(kwargs, message) -> None:
    kwargs.setdefault("strategy", MigrationStrategy.MIGRATION_STRATEGY_UNSPECIFIED)
    with pytest.raises(InvalidArgumentError) as raised:
        migrate_key_request("k", **kwargs)
    assert message in str(raised.value)
