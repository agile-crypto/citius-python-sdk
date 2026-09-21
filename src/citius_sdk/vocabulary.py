"""Intent-oriented request vocabulary for building Citius requests.

This module gives the Python SDK the same consolidated surface the Go SDK
exposes: callers pick a :class:`Scope` (the operational intent) and layer
optional filter properties — :class:`SecurityProperties`,
:class:`ProviderRequirements`, and primitive-specific properties — without ever
touching the generated ``ScopeSpecification`` oneof or the
``UniversalSecurityProperties`` proto.

The vocabulary mirrors ``citius-core`` (``scope.go``, ``security_properties.go``)
and ``citius-go-sdk/client/common`` so both SDKs stay semantically aligned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum

from citius_api.types import common_pb2 as _common
from citius_api.types import implementation_pb2 as _impl

# ── Primitive ───────────────────────────────────────────────────────────────


class Primitive(Enum):
    """The cryptographic primitive a scope belongs to."""

    UNKNOWN = "unknown"
    SIGNATURE = "signature"
    AEAD = "aead"
    MAC = "mac"
    KEM = "kem"
    KEY_AGREEMENT = "key_agreement"
    KDF = "kdf"
    HASH = "hash"
    KEY_WRAPPING = "key_wrapping"
    SYMMETRIC_CIPHER = "symmetric_cipher"
    DISK_ENCRYPTION = "disk_encryption"
    GENERIC_SECRET = "generic_secret"
    ASYMMETRIC_ENCRYPTION = "asymmetric_encryption"


# ── Scope ─────────────────────────────────────────────────────────────────────

# Each Scope maps to (ScopeSpecification oneof arm, proto scope-enum value). The
# arm is the field name on ScopeSpecification; the value is the per-primitive
# proto enum constant. This mirrors citius-core's scopeToProto table.
_SCOPE_TABLE: dict[str, tuple[Primitive, str, int]] = {
    # Signature
    "SIGNATURE_STANDARD": (Primitive.SIGNATURE, "signature", _common.SIGNATURE_SCOPE_STANDARD),
    "SIGNATURE_WITH_CONTEXT": (
        Primitive.SIGNATURE,
        "signature",
        _common.SIGNATURE_SCOPE_WITH_CONTEXT,
    ),
    "SIGNATURE_PREHASHED": (Primitive.SIGNATURE, "signature", _common.SIGNATURE_SCOPE_PREHASHED),
    "SIGNATURE_PREHASHED_WITH_CONTEXT": (
        Primitive.SIGNATURE,
        "signature",
        _common.SIGNATURE_SCOPE_PREHASHED_WITH_CONTEXT,
    ),
    # AEAD
    "AEAD_STANDARD": (Primitive.AEAD, "aead", _common.AEAD_SCOPE_STANDARD),
    "AEAD_DETERMINISTIC": (Primitive.AEAD, "aead", _common.AEAD_SCOPE_DETERMINISTIC),
    "AEAD_STREAMING": (Primitive.AEAD, "aead", _common.AEAD_SCOPE_STREAMING),
    # MAC
    "MAC_STANDARD": (Primitive.MAC, "mac", _common.MAC_SCOPE_STANDARD),
    "MAC_STREAMING": (Primitive.MAC, "mac", _common.MAC_SCOPE_STREAMING),
    # KEM
    "KEM_STANDARD": (Primitive.KEM, "kem", _common.KEM_SCOPE_STANDARD),
    "KEM_HYBRID": (Primitive.KEM, "kem", _common.KEM_SCOPE_HYBRID),
    # Key agreement
    "KEY_AGREEMENT_STANDARD": (
        Primitive.KEY_AGREEMENT,
        "key_agreement",
        _common.KEY_AGREEMENT_SCOPE_STANDARD,
    ),
    "KEY_AGREEMENT_HYBRID": (
        Primitive.KEY_AGREEMENT,
        "key_agreement",
        _common.KEY_AGREEMENT_SCOPE_HYBRID,
    ),
    # KDF
    "KDF_EXTRACT_EXPAND": (Primitive.KDF, "kdf", _common.KDF_SCOPE_EXTRACT_EXPAND),
    "KDF_PASSWORD": (Primitive.KDF, "kdf", _common.KDF_SCOPE_PASSWORD),
    "KDF_AGREEMENT": (Primitive.KDF, "kdf", _common.KDF_SCOPE_AGREEMENT),
    "KDF_COUNTER": (Primitive.KDF, "kdf", _common.KDF_SCOPE_COUNTER),
    "KDF_TLS": (Primitive.KDF, "kdf", _common.KDF_SCOPE_TLS),
    "KDF_GOST": (Primitive.KDF, "kdf", _common.KDF_SCOPE_GOST),
    "KDF_VENDOR": (Primitive.KDF, "kdf", _common.KDF_SCOPE_VENDOR),
    # Hash
    "HASH_STANDARD": (Primitive.HASH, "hash", _common.HASH_SCOPE_STANDARD),
    "HASH_XOF": (Primitive.HASH, "hash", _common.HASH_SCOPE_XOF),
    # Key wrapping
    "KEY_WRAPPING_STANDARD": (
        Primitive.KEY_WRAPPING,
        "key_wrapping",
        _common.KEY_WRAPPING_SCOPE_STANDARD,
    ),
    "KEY_WRAPPING_WITH_PADDING": (
        Primitive.KEY_WRAPPING,
        "key_wrapping",
        _common.KEY_WRAPPING_SCOPE_WITH_PADDING,
    ),
    # Symmetric cipher
    "SYMMETRIC_CIPHER_BLOCK": (
        Primitive.SYMMETRIC_CIPHER,
        "symmetric_cipher",
        _common.SYMMETRIC_CIPHER_SCOPE_BLOCK,
    ),
    "SYMMETRIC_CIPHER_STREAM": (
        Primitive.SYMMETRIC_CIPHER,
        "symmetric_cipher",
        _common.SYMMETRIC_CIPHER_SCOPE_STREAM,
    ),
    # Disk encryption
    "DISK_ENCRYPTION_STANDARD": (
        Primitive.DISK_ENCRYPTION,
        "disk_encryption",
        _common.DISK_ENCRYPTION_SCOPE_STANDARD,
    ),
    # Generic secret
    "GENERIC_SECRET_STANDARD": (
        Primitive.GENERIC_SECRET,
        "generic_secret",
        _common.GENERIC_SECRET_SCOPE_STANDARD,
    ),
    # Asymmetric encryption (proto-complete; citius-core does not yet map these)
    "ASYMMETRIC_ENCRYPTION_STANDARD": (
        Primitive.ASYMMETRIC_ENCRYPTION,
        "asymmetric_encryption",
        _common.ASYMMETRIC_ENCRYPTION_SCOPE_STANDARD,
    ),
    "ASYMMETRIC_ENCRYPTION_RAW": (
        Primitive.ASYMMETRIC_ENCRYPTION,
        "asymmetric_encryption",
        _common.ASYMMETRIC_ENCRYPTION_SCOPE_RAW,
    ),
}


class Scope(Enum):
    """The operational variant of a cryptographic primitive.

    Each member identifies the set of parameters a caller must supply,
    independent of the concrete algorithm chosen by policy. Use
    :meth:`build_scope_spec` (or pass ``scope=`` to ``create_key_request``) to
    turn a scope plus optional properties into a ``ScopeSpecification``.
    """

    SIGNATURE_STANDARD = "SIGNATURE_STANDARD"
    SIGNATURE_WITH_CONTEXT = "SIGNATURE_WITH_CONTEXT"
    SIGNATURE_PREHASHED = "SIGNATURE_PREHASHED"
    SIGNATURE_PREHASHED_WITH_CONTEXT = "SIGNATURE_PREHASHED_WITH_CONTEXT"
    AEAD_STANDARD = "AEAD_STANDARD"
    AEAD_DETERMINISTIC = "AEAD_DETERMINISTIC"
    AEAD_STREAMING = "AEAD_STREAMING"
    MAC_STANDARD = "MAC_STANDARD"
    MAC_STREAMING = "MAC_STREAMING"
    KEM_STANDARD = "KEM_STANDARD"
    KEM_HYBRID = "KEM_HYBRID"
    KEY_AGREEMENT_STANDARD = "KEY_AGREEMENT_STANDARD"
    KEY_AGREEMENT_HYBRID = "KEY_AGREEMENT_HYBRID"
    KDF_EXTRACT_EXPAND = "KDF_EXTRACT_EXPAND"
    KDF_PASSWORD = "KDF_PASSWORD"
    KDF_AGREEMENT = "KDF_AGREEMENT"
    KDF_COUNTER = "KDF_COUNTER"
    KDF_TLS = "KDF_TLS"
    KDF_GOST = "KDF_GOST"
    KDF_VENDOR = "KDF_VENDOR"
    HASH_STANDARD = "HASH_STANDARD"
    HASH_XOF = "HASH_XOF"
    KEY_WRAPPING_STANDARD = "KEY_WRAPPING_STANDARD"
    KEY_WRAPPING_WITH_PADDING = "KEY_WRAPPING_WITH_PADDING"
    SYMMETRIC_CIPHER_BLOCK = "SYMMETRIC_CIPHER_BLOCK"
    SYMMETRIC_CIPHER_STREAM = "SYMMETRIC_CIPHER_STREAM"
    DISK_ENCRYPTION_STANDARD = "DISK_ENCRYPTION_STANDARD"
    GENERIC_SECRET_STANDARD = "GENERIC_SECRET_STANDARD"
    ASYMMETRIC_ENCRYPTION_STANDARD = "ASYMMETRIC_ENCRYPTION_STANDARD"
    ASYMMETRIC_ENCRYPTION_RAW = "ASYMMETRIC_ENCRYPTION_RAW"

    @property
    def primitive(self) -> Primitive:
        """Return the primitive this scope belongs to."""
        return _SCOPE_TABLE[self.value][0]

    @property
    def spec_arm(self) -> str:
        """Return the ScopeSpecification oneof arm this scope populates."""
        return _SCOPE_TABLE[self.value][1]

    def to_proto_value(self) -> int:
        """Return the per-primitive proto scope-enum value for this scope."""
        return _SCOPE_TABLE[self.value][2]


# ── Security and provider enums ────────────────────────────────────────────────


class NistSecurityLevel(IntEnum):
    """NIST post-quantum security level (categories 1–5)."""

    UNSPECIFIED = _common.NIST_SECURITY_LEVEL_UNSPECIFIED
    LEVEL_1 = _common.NIST_SECURITY_LEVEL_1
    LEVEL_2 = _common.NIST_SECURITY_LEVEL_2
    LEVEL_3 = _common.NIST_SECURITY_LEVEL_3
    LEVEL_4 = _common.NIST_SECURITY_LEVEL_4
    LEVEL_5 = _common.NIST_SECURITY_LEVEL_5


class NistStatus(IntEnum):
    """NIST approval status of an algorithm."""

    UNSPECIFIED = _common.NIST_STATUS_UNSPECIFIED
    APPROVED = _common.NIST_STATUS_APPROVED
    RECOMMENDED = _common.NIST_STATUS_RECOMMENDED
    ACCEPTABLE = _common.NIST_STATUS_ACCEPTABLE
    DEPRECATED = _common.NIST_STATUS_DEPRECATED
    FORBIDDEN = _common.NIST_STATUS_FORBIDDEN


class Fips140Level(IntEnum):
    """FIPS 140 certification level (1–4)."""

    UNSPECIFIED = _impl.FIPS_140_LEVEL_UNSPECIFIED
    LEVEL_1 = _impl.FIPS_140_LEVEL_1
    LEVEL_2 = _impl.FIPS_140_LEVEL_2
    LEVEL_3 = _impl.FIPS_140_LEVEL_3
    LEVEL_4 = _impl.FIPS_140_LEVEL_4


# ── SecurityProperties ─────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SecurityProperties:
    """Algorithm security requirements used to filter templates.

    Behaves as a filter on the set of templates considered for a key: only
    templates satisfying these properties are eligible. Maps to the proto
    ``UniversalSecurityProperties``.
    """

    security_strength_bits: int = 0
    nist_security_level: NistSecurityLevel = NistSecurityLevel.UNSPECIFIED
    quantum_safe: bool | None = None
    nist_status: NistStatus = NistStatus.UNSPECIFIED
    fips_approved: bool | None = None

    def to_proto(self) -> _common.UniversalSecurityProperties:
        props = _common.UniversalSecurityProperties(
            security_strength_bits=self.security_strength_bits,
            nist_security_level=int(self.nist_security_level),
            nist_status=int(self.nist_status),
        )
        # quantum_safe and fips_approved are proto3 optional; only set when the
        # caller expressed an explicit preference so absence stays absent.
        if self.quantum_safe is not None:
            props.quantum_safe = self.quantum_safe
        if self.fips_approved is not None:
            props.fips_approved = self.fips_approved
        return props


# ── ProviderRequirements ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ProviderRequirements:
    """Requirements the provider hosting a key must satisfy.

    Maps to the proto ``ProviderRequirements`` and mirrors the Go SDK's
    ``common.ProviderRequirements`` (plus ``memory_safe`` which the proto
    defines).
    """

    fips_140_certified: bool = False
    min_fips_level: Fips140Level = Fips140Level.UNSPECIFIED
    common_criteria_certified: bool = False
    formally_verified: bool = False
    memory_safe: bool = False
    constant_time: bool = False
    side_channel_hardened: bool = False
    no_known_cve: bool = False
    prefer_hardware_accelerated: bool = False
    additional_properties: dict[str, str] = field(default_factory=dict)

    def to_proto(self) -> _impl.ProviderRequirements:
        return _impl.ProviderRequirements(
            fips_140_certified=self.fips_140_certified,
            min_fips_level=int(self.min_fips_level),
            common_criteria_certified=self.common_criteria_certified,
            formally_verified=self.formally_verified,
            memory_safe=self.memory_safe,
            constant_time=self.constant_time,
            side_channel_hardened=self.side_channel_hardened,
            no_known_cve=self.no_known_cve,
            prefer_hardware_accelerated=self.prefer_hardware_accelerated,
            additional=dict(self.additional_properties),
        )


# ── Primitive-specific properties ──────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SignatureProperties:
    """Signature-specific template requirements."""

    non_malleable: bool | None = None
    deterministic: bool | None = None

    @property
    def primitive(self) -> Primitive:
        return Primitive.SIGNATURE


@dataclass(frozen=True, slots=True)
class AeadProperties:
    """AEAD-specific template requirements."""

    nonce_misuse_resistant: bool | None = None

    @property
    def primitive(self) -> Primitive:
        return Primitive.AEAD


@dataclass(frozen=True, slots=True)
class KeyAgreementProperties:
    """Key-agreement-specific template requirements."""

    forward_secrecy: bool | None = None

    @property
    def primitive(self) -> Primitive:
        return Primitive.KEY_AGREEMENT


@dataclass(frozen=True, slots=True)
class KdfProperties:
    """KDF-specific template requirements."""

    memory_hard: bool | None = None

    @property
    def primitive(self) -> Primitive:
        return Primitive.KDF


# The union of primitive-property types. Every one exposes a ``primitive``
# property so the scope-spec builder can validate the primitive matches.
PrimitiveProperties = SignatureProperties | AeadProperties | KeyAgreementProperties | KdfProperties


# ── Scope specification builder ────────────────────────────────────────────────


def build_scope_spec(
    scope: Scope,
    *,
    security: SecurityProperties | None = None,
    primitive: PrimitiveProperties | None = None,
    additional: dict[str, str] | None = None,
) -> _common.ScopeSpecification:
    """Build a ``ScopeSpecification`` from a scope plus optional properties.

    ``security`` and ``additional`` apply to any scope; ``primitive`` carries
    the extra requirements a specific primitive supports (e.g. non-malleable
    signatures, nonce-misuse-resistant AEAD). Raises ``ValueError`` when the
    primitive properties do not match the scope's primitive, matching
    citius-core's ``NewScopeSpecification`` contract.
    """
    if primitive is not None and primitive.primitive is not scope.primitive:
        raise ValueError(
            f"primitive properties for {primitive.primitive.value!r} do not match "
            f"scope {scope.value!r} (primitive {scope.primitive.value!r})"
        )

    arm = scope.spec_arm
    arm_kwargs: dict[str, object] = {"scope": scope.to_proto_value()}
    if security is not None:
        arm_kwargs["security"] = security.to_proto()
    if additional:
        arm_kwargs["additional_properties"] = dict(additional)
    _apply_primitive_properties(arm_kwargs, primitive)

    arm_cls = _ARM_MESSAGE[arm]
    return _common.ScopeSpecification(**{arm: arm_cls(**arm_kwargs)})


# ScopeSpecification oneof arm -> the per-primitive spec message class.
_ARM_MESSAGE: dict[str, type] = {
    "signature": _common.SignatureScopeSpec,
    "aead": _common.AeadScopeSpec,
    "mac": _common.MacScopeSpec,
    "kem": _common.KemScopeSpec,
    "key_agreement": _common.KeyAgreementScopeSpec,
    "kdf": _common.KdfScopeSpec,
    "hash": _common.HashScopeSpec,
    "key_wrapping": _common.KeyWrappingScopeSpec,
    "symmetric_cipher": _common.SymmetricCipherScopeSpec,
    "generic_secret": _common.GenericSecretScopeSpec,
    "disk_encryption": _common.DiskEncryptionScopeSpec,
    "asymmetric_encryption": _common.AsymmetricEncryptionScopeSpec,
}


def _apply_primitive_properties(
    arm_kwargs: dict[str, object], primitive: PrimitiveProperties | None
) -> None:
    """Set the primitive-specific proto fields for the matching arm, if any.

    Only fields the caller expressed an explicit preference for (non-None) are
    set, so absence stays absent on the proto3-optional booleans.
    """
    if primitive is None:
        return
    if isinstance(primitive, SignatureProperties):
        if primitive.non_malleable is not None:
            arm_kwargs["non_malleable"] = primitive.non_malleable
        if primitive.deterministic is not None:
            arm_kwargs["deterministic"] = primitive.deterministic
    elif isinstance(primitive, AeadProperties):
        if primitive.nonce_misuse_resistant is not None:
            arm_kwargs["nonce_misuse_resistant"] = primitive.nonce_misuse_resistant
    elif isinstance(primitive, KeyAgreementProperties):
        if primitive.forward_secrecy is not None:
            arm_kwargs["forward_secrecy"] = primitive.forward_secrecy
    elif isinstance(primitive, KdfProperties):
        if primitive.memory_hard is not None:
            arm_kwargs["memory_hard"] = primitive.memory_hard
