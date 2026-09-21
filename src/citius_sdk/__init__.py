"""Async Python client SDK for Citius."""

from citius_sdk.auth import (
    CallableTokenProvider,
    StaticTokenProvider,
    TokenProvider,
)
from citius_sdk.config import ClientConfig, TLSConfig
from citius_sdk.errors import (
    AlreadyExistsError,
    AuthenticationError,
    CitiusError,
    DeadlineExceededError,
    FailedPreconditionError,
    InvalidArgumentError,
    NotFoundError,
    PermissionDeniedError,
    UnavailableError,
    UnimplementedError,
    from_rpc_error,
)
from citius_sdk.metadata import OperationMetadata
from citius_sdk.version import (
    check_api_compatibility,
    compatible_api_version,
    installed_api_version,
)
from citius_sdk.vocabulary import (
    AeadProperties,
    Fips140Level,
    KdfProperties,
    KeyAgreementProperties,
    NistSecurityLevel,
    NistStatus,
    Primitive,
    PrimitiveProperties,
    ProviderRequirements,
    Scope,
    SecurityProperties,
    SignatureProperties,
    build_scope_spec,
)

__all__ = [
    "AeadProperties",
    "AlreadyExistsError",
    "AuthenticationError",
    "CallableTokenProvider",
    "CitiusError",
    "ClientConfig",
    "DeadlineExceededError",
    "FailedPreconditionError",
    "Fips140Level",
    "InvalidArgumentError",
    "KdfProperties",
    "KeyAgreementProperties",
    "NistSecurityLevel",
    "NistStatus",
    "NotFoundError",
    "OperationMetadata",
    "PermissionDeniedError",
    "Primitive",
    "PrimitiveProperties",
    "ProviderRequirements",
    "Scope",
    "SecurityProperties",
    "SignatureProperties",
    "StaticTokenProvider",
    "TLSConfig",
    "TokenProvider",
    "UnavailableError",
    "UnimplementedError",
    "build_scope_spec",
    "check_api_compatibility",
    "compatible_api_version",
    "from_rpc_error",
    "installed_api_version",
]
