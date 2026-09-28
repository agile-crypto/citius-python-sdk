"""Key management service client."""

from __future__ import annotations

import grpc
from citius_api.messages.key_management_pb2 import (
    CreateKeyRequest,
    CreateKeyResponse,
    KeyMetadata,
    ListKeysRequest,
    ListKeysResponse,
    MigrateKeyRequest,
    MigrateKeyResponse,
    MigrationStrategy,
    ProviderTarget,
    ReadKeyRequest,
    ReadKeyResponse,
    StrategyOption,
    TransformKeyRequest,
    TransformKeyResponse,
    ValidateKeyOperationRequest,
    ValidateKeyOperationResponse,
    ValidateMigrateIntent,
)
from citius_api.services.key_management_service_pb2_grpc import KeyManagementServiceStub
from citius_api.types.common_pb2 import KeyLifecycleState, KeyOrigin

from citius_sdk.auth import TokenProvider
from citius_sdk.channel import create_channel
from citius_sdk.config import ClientConfig
from citius_sdk.errors import InvalidArgumentError, map_rpc_errors
from citius_sdk.vocabulary import (
    PrimitiveProperties,
    ProviderRequirements,
    Scope,
    SecurityProperties,
    build_scope_spec,
)


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
    scope: Scope | None = None,
    template_id: str = "",
    provider_id: str = "",
    security_properties: SecurityProperties | None = None,
    primitive_properties: PrimitiveProperties | None = None,
    additional_properties: dict[str, str] | None = None,
    provider_requirements: ProviderRequirements | None = None,
    provider_configuration: dict[str, str] | None = None,
) -> CreateKeyRequest:
    """Build a CreateKeyRequest from an intent-oriented request vocabulary.

    ``scope`` selects the operational intent (e.g. ``Scope.AEAD_STANDARD``);
    ``security_properties``, ``primitive_properties`` and ``additional_properties``
    layer template filters onto that scope; ``provider_requirements`` and
    ``provider_configuration`` constrain the hosting provider. ``template_id``
    and ``provider_id`` pin an explicit template/provider instead of letting the
    server select one. A scope is required unless a ``template_id`` is given,
    since the server needs a scope specification to select a template.
    """
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _require(
        errors,
        scope is not None or bool(template_id),
        "a scope or template_id is required",
    )
    if scope is None and (
        security_properties is not None or primitive_properties is not None or additional_properties
    ):
        errors.append("scope filter properties require a scope")
    _raise_if_invalid("create key request", errors)

    request = CreateKeyRequest(
        name=name, policy=policy, template_id=template_id, provider_id=provider_id
    )
    if scope is not None:
        try:
            request.scope_spec.CopyFrom(
                build_scope_spec(
                    scope,
                    security=security_properties,
                    primitive=primitive_properties,
                    additional=additional_properties,
                )
            )
        except ValueError as exc:
            raise InvalidArgumentError(
                grpc.StatusCode.INVALID_ARGUMENT, f"invalid create key request: {exc}"
            ) from exc
    if provider_requirements is not None:
        request.provider_requirements.CopyFrom(provider_requirements.to_proto())
    if provider_configuration:
        request.provider_configuration.update(provider_configuration)
    return request


def read_key_request(name: str, *, version: int | None = None) -> ReadKeyRequest:
    """Build a ReadKeyRequest for a key, optionally pinned to a version."""
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _raise_if_invalid("read key request", errors)
    request = ReadKeyRequest(name=name)
    if version is not None:
        request.version = version
    return request


def list_keys_request(
    *,
    provider_id: str = "",
    policy: str = "",
    lifecycle_state: KeyLifecycleState.ValueType = (
        KeyLifecycleState.KEY_LIFECYCLE_STATE_UNSPECIFIED
    ),
    page_size: int = 0,
    page_token: str = "",
) -> ListKeysRequest:
    """Build a ListKeysRequest.

    Each set filter narrows the listing; ``page_size`` 0 returns every match.
    Pass a response's ``next_page_token`` as ``page_token`` for the next page.
    """
    errors: list[str] = []
    _require(errors, page_size >= 0, "page_size must not be negative")
    _raise_if_invalid("list keys request", errors)
    return ListKeysRequest(
        provider_id=provider_id,
        policy=policy,
        lifecycle_state=lifecycle_state,
        page_size=page_size,
        page_token=page_token,
    )


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


def migrate_key_request(
    name: str,
    *,
    strategy: MigrationStrategy.ValueType,
    target_instance_id: str = "",
    target_provider_id: str = "",
) -> MigrateKeyRequest:
    """Build a MigrateKeyRequest to move a key to another provider.

    Name exactly one target: a provider instance (``target_instance_id``) or a
    provider type (``target_provider_id``). The key keeps its template and scope.
    """
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _require(
        errors,
        bool(target_instance_id) != bool(target_provider_id),
        "exactly one of target_instance_id or target_provider_id is required",
    )
    _require(
        errors,
        strategy != MigrationStrategy.MIGRATION_STRATEGY_UNSPECIFIED,
        "strategy is unspecified",
    )
    _raise_if_invalid("migrate key request", errors)
    request = MigrateKeyRequest(name=name, strategy=strategy)
    if target_instance_id:
        request.target_instance_id = target_instance_id
    else:
        request.provider_target.CopyFrom(ProviderTarget(provider_id=target_provider_id))
    return request


def validate_migration_request(
    name: str,
    *,
    target_instance_id: str = "",
    target_provider_id: str = "",
    preferred_strategy: MigrationStrategy.ValueType = (
        MigrationStrategy.MIGRATION_STRATEGY_UNSPECIFIED
    ),
) -> ValidateKeyOperationRequest:
    """Build a ValidateKeyOperationRequest asking how a key could migrate.

    Name exactly one target, as for :func:`migrate_key_request`. The server
    assesses every strategy without side effects; ``preferred_strategy``, when
    set, is the one the caller intends to use.
    """
    errors: list[str] = []
    _require(errors, bool(name), "name is empty")
    _require(
        errors,
        bool(target_instance_id) != bool(target_provider_id),
        "exactly one of target_instance_id or target_provider_id is required",
    )
    _raise_if_invalid("validate migration request", errors)
    intent = ValidateMigrateIntent(preferred_strategy=preferred_strategy)
    if target_instance_id:
        intent.target_instance_id = target_instance_id
    else:
        intent.target_provider_id = target_provider_id
    return ValidateKeyOperationRequest(name=name, migrate=intent)


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

    @property
    def provider(self) -> str:
        """The provider instance holding the current version."""
        return self._inner.provider

    @property
    def extractable(self) -> bool:
        """Whether the current version's material may leave its provider."""
        return self._inner.extractable

    @property
    def lifecycle_state(self) -> KeyLifecycleState.ValueType:
        return self._inner.lifecycle_state

    @property
    def origin(self) -> KeyOrigin.ValueType:
        """How the current version's material came to exist."""
        return self._inner.origin


class CreateKeyResult:
    """Outcome of a key creation."""

    def __init__(self, inner: CreateKeyResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> CreateKeyResponse:
        """The full underlying response message."""
        return self._inner

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
    def proto(self) -> ReadKeyResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def key_metadata(self) -> KeyMetadataView | None:
        return (
            KeyMetadataView(self._inner.key_metadata)
            if self._inner.HasField("key_metadata")
            else None
        )


class ListKeysResult:
    """One page of a key listing, ordered by name."""

    def __init__(self, inner: ListKeysResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> ListKeysResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def keys(self) -> list[KeyMetadataView]:
        return [KeyMetadataView(k) for k in self._inner.keys]

    @property
    def next_page_token(self) -> str:
        """Token for the next page; empty on the last page."""
        return self._inner.next_page_token


class TransformKeyResult:
    """Outcome of a key transformation."""

    def __init__(self, inner: TransformKeyResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> TransformKeyResponse:
        """The full underlying response message."""
        return self._inner

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


class MigrateKeyResult:
    """Outcome of a key migration."""

    def __init__(self, inner: MigrateKeyResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> MigrateKeyResponse:
        """The full underlying response message."""
        return self._inner

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

    @property
    def key_bytes_preserved(self) -> bool:
        return self._inner.result.key_bytes_preserved

    @property
    def source_instance_id(self) -> str:
        return self._inner.result.source_instance_id

    @property
    def target_instance_id(self) -> str:
        return self._inner.result.target_instance_id


class StrategyOptionView:
    """One assessed strategy: whether it would succeed now, and why not."""

    def __init__(self, inner: StrategyOption) -> None:
        self._inner = inner

    @property
    def proto(self) -> StrategyOption:
        return self._inner

    @property
    def strategy(self) -> MigrationStrategy.ValueType:
        return self._inner.strategy

    @property
    def strategy_name(self) -> str:
        return MigrationStrategy.Name(self._inner.strategy)

    @property
    def feasible(self) -> bool:
        return self._inner.feasible

    @property
    def infeasibility_reason(self) -> str:
        return self._inner.infeasibility_reason

    @property
    def security_notes(self) -> list[str]:
        return list(self._inner.security_notes)


class ValidateKeyOperationResult:
    """The server's side-effect-free assessment of a key operation."""

    def __init__(self, inner: ValidateKeyOperationResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> ValidateKeyOperationResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def options(self) -> list[StrategyOptionView]:
        return [StrategyOptionView(o) for o in self._inner.options]

    @property
    def feasible_strategies(self) -> list[MigrationStrategy.ValueType]:
        return [o.strategy for o in self._inner.options if o.feasible]

    @property
    def recommended_strategy(self) -> MigrationStrategy.ValueType:
        """The recommended strategy; UNSPECIFIED when none is feasible."""
        return self._inner.recommended_strategy

    @property
    def recommendation_reason(self) -> str:
        return self._inner.recommendation_reason

    @property
    def current_instance_id(self) -> str:
        return self._inner.current_state.instance_id

    @property
    def current_template_id(self) -> str:
        return self._inner.current_state.template_id

    @property
    def current_extractable(self) -> bool:
        return self._inner.current_state.extractable


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
    async def list_keys(
        self, request: ListKeysRequest | None = None, *, timeout: float | None = None
    ) -> ListKeysResult:
        response = await self._stub.ListKeys(
            request or ListKeysRequest(), timeout=self._deadline(timeout)
        )
        return ListKeysResult(response)

    @map_rpc_errors
    async def transform_key(
        self, request: TransformKeyRequest, *, timeout: float | None = None
    ) -> TransformKeyResult:
        response = await self._stub.TransformKey(request, timeout=self._deadline(timeout))
        return TransformKeyResult(response)

    @map_rpc_errors
    async def migrate_key(
        self, request: MigrateKeyRequest, *, timeout: float | None = None
    ) -> MigrateKeyResult:
        response = await self._stub.MigrateKey(request, timeout=self._deadline(timeout))
        return MigrateKeyResult(response)

    @map_rpc_errors
    async def validate_key_operation(
        self, request: ValidateKeyOperationRequest, *, timeout: float | None = None
    ) -> ValidateKeyOperationResult:
        response = await self._stub.ValidateKeyOperation(request, timeout=self._deadline(timeout))
        return ValidateKeyOperationResult(response)

    async def close(self, grace: float | None = None) -> None:
        """Close the channel when this client created it."""
        if self._close_channel:
            await self._channel.close(grace)

    async def __aenter__(self) -> KeyManagementClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()
