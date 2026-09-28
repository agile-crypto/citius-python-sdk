from __future__ import annotations

import grpc
import pytest
import pytest_asyncio
from citius_api.messages.key_management_pb2 import (
    CreateKeyResponse,
    KeyMetadata,
    ListKeysResponse,
    MigrateKeyResponse,
    MigrationStrategy,
    ReadKeyResponse,
    TransformKeyResponse,
    ValidateKeyOperationResponse,
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
    list_keys_request,
    migrate_key_request,
    read_key_request,
    transform_key_request,
    validate_migration_request,
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

    async def ListKeys(self, request, context):  # noqa: N802
        await self._guard(context)
        names = [n for n in ("alpha", "bravo", "charlie") if n != _DENIED]
        if request.provider_id:
            names = [n for n in names if n == "bravo"]
        start = int(request.page_token or 0)
        end = start + request.page_size if request.page_size else len(names)
        response = ListKeysResponse()
        for name in names[start:end]:
            response.keys.add(name=name, provider=request.provider_id or "software")
        if end < len(names):
            response.next_page_token = str(end)
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
        response.result.source_provider_id = "software"
        response.result.target_provider_id = "openssl"
        if target == "openssl-fips":
            response.result.target_implementation.fips_140.certified = True
        if request.strategy == MigrationStrategy.MIGRATION_STRATEGY_REKEY_AND_ARCHIVE:
            response.archived_key_info.archived_key_name = request.name
            response.archived_key_info.provider_id = "software"
        return response

    async def ValidateKeyOperation(self, request, context):  # noqa: N802
        await self._guard(context)
        if request.WhichOneof("intent") != "migrate":
            await context.abort(grpc.StatusCode.UNIMPLEMENTED, "only migrate")
        response = ValidateKeyOperationResponse(
            recommended_strategy=MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH,
            recommendation_reason="keeps the key bytes",
        )
        response.current_state.instance_id = "software"
        response.current_state.extractable = True
        response.options.add(
            strategy=MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH,
            feasible=True,
            security_notes=["material leaves software in plaintext"],
        )
        response.options.add(
            strategy=MigrationStrategy.MIGRATION_STRATEGY_WRAPPED_TRANSFER,
            feasible=False,
            infeasibility_reason="no provider wraps",
        )
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


@pytest.mark.asyncio
async def test_list_keys_pages_and_filters(key_endpoint) -> None:
    async with KeyManagementClient.connect(
        _config(key_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        everything = await client.list_keys()
        assert [k.name for k in everything.keys] == ["alpha", "bravo", "charlie"]
        assert everything.next_page_token == ""

        first = await client.list_keys(list_keys_request(page_size=2))
        assert [k.name for k in first.keys] == ["alpha", "bravo"]
        rest = await client.list_keys(
            list_keys_request(page_size=2, page_token=first.next_page_token)
        )
        assert [k.name for k in rest.keys] == ["charlie"]
        assert rest.next_page_token == ""

        on_openssl = await client.list_keys(list_keys_request(provider_id="openssl"))
        assert [(k.name, k.provider) for k in on_openssl.keys] == [("bravo", "openssl")]


def test_list_keys_request_rejects_negative_page_size() -> None:
    with pytest.raises(InvalidArgumentError) as raised:
        list_keys_request(page_size=-1)
    assert "page_size" in str(raised.value)


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
    assert migrated.strategy_used == MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH
    assert migrated.source_provider_id == "software"
    assert migrated.target_provider_id == "openssl"
    assert migrated.target_implementation is None
    assert migrated.archived_key_name is None
    assert migrated.archived_provider_id is None


@pytest.mark.asyncio
async def test_migrate_key_rekey_and_archive_reports_the_archive(key_endpoint) -> None:
    async with KeyManagementClient.connect(
        _config(key_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        migrated = await client.migrate_key(
            migrate_key_request(
                "demo-key",
                strategy=MigrationStrategy.MIGRATION_STRATEGY_REKEY_AND_ARCHIVE,
                target_instance_id="openssl-fips",
            )
        )
    assert migrated.key_bytes_preserved is False
    assert migrated.archived_key_name == "demo-key"
    assert migrated.archived_provider_id == "software"
    assert migrated.target_implementation is not None
    assert migrated.target_implementation.fips_140.certified is True


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


@pytest.mark.asyncio
async def test_validate_migration(key_endpoint) -> None:
    async with KeyManagementClient.connect(
        _config(key_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        assessed = await client.validate_key_operation(
            validate_migration_request("demo-key", target_instance_id="openssl")
        )
    assert assessed.recommended_strategy == MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH
    assert assessed.recommendation_reason == "keeps the key bytes"
    assert assessed.current_instance_id == "software"
    assert assessed.current_extractable is True
    assert assessed.feasible_strategies == [MigrationStrategy.MIGRATION_STRATEGY_PROVIDER_SWITCH]
    switch, wrapped = assessed.options
    assert switch.strategy_name == "MIGRATION_STRATEGY_PROVIDER_SWITCH"
    assert switch.security_notes == ["material leaves software in plaintext"]
    assert wrapped.feasible is False
    assert wrapped.infeasibility_reason == "no provider wraps"


def test_validate_migration_request_targets() -> None:
    by_type = validate_migration_request("k", target_provider_id="openssl")
    assert by_type.WhichOneof("intent") == "migrate"
    assert by_type.migrate.WhichOneof("target") == "target_provider_id"
    assert by_type.migrate.target_provider_id == "openssl"


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"target_instance_id": "a", "target_provider_id": "b"}],
)
def test_validate_migration_request_needs_one_target(kwargs) -> None:
    with pytest.raises(InvalidArgumentError) as raised:
        validate_migration_request("k", **kwargs)
    assert "exactly one of" in str(raised.value)
