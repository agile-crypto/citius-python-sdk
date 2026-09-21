"""Operation parameters and signature contexts for crypto requests.

The :mod:`citius_sdk.vocabulary` module covers *key-creation* intent (scopes and
filter properties). This module covers *per-operation* parameters: the
``*_params`` oneof on encrypt/decrypt requests and the ``*_context`` oneof on
sign/verify requests. Callers pass one of these dataclasses to the crypto
request builders instead of touching the generated
``AeadEncryptParams`` / ``SignatureDomainContext`` protos directly.

Each dataclass exposes a ``.to_proto()`` that returns the matching generated
message; the request builders route it into the correct oneof arm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from citius_api.types import algorithm_params_pb2 as _alg
from citius_api.types import operation_params_pb2 as _params

# ── Hash algorithm (for digest sign/verify) ──────────────────────────────────


class HashAlgorithm(IntEnum):
    """Hash algorithm identifiers for prehashed (digest) sign/verify.

    Values mirror ``caas.crypto.v1.HashAlgorithm`` so callers do not import the
    generated enum. Use :data:`UNSPECIFIED` to let the server infer the hash
    from the key/template, or pass an explicit OID via the builder instead.
    """

    UNSPECIFIED = _alg.HASH_ALGORITHM_UNSPECIFIED
    SHA256 = _alg.HASH_ALGORITHM_SHA256
    SHA384 = _alg.HASH_ALGORITHM_SHA384
    SHA512 = _alg.HASH_ALGORITHM_SHA512
    SHA512_256 = _alg.HASH_ALGORITHM_SHA512_256
    SHA224 = _alg.HASH_ALGORITHM_SHA224
    SHA512_224 = _alg.HASH_ALGORITHM_SHA512_224
    SHA3_256 = _alg.HASH_ALGORITHM_SHA3_256
    SHA3_384 = _alg.HASH_ALGORITHM_SHA3_384
    SHA3_512 = _alg.HASH_ALGORITHM_SHA3_512
    SHA3_224 = _alg.HASH_ALGORITHM_SHA3_224
    SHAKE128 = _alg.HASH_ALGORITHM_SHAKE128
    SHAKE256 = _alg.HASH_ALGORITHM_SHAKE256
    BLAKE2B_256 = _alg.HASH_ALGORITHM_BLAKE2B_256
    BLAKE2B_384 = _alg.HASH_ALGORITHM_BLAKE2B_384
    BLAKE2B_512 = _alg.HASH_ALGORITHM_BLAKE2B_512
    BLAKE2S_256 = _alg.HASH_ALGORITHM_BLAKE2S_256
    BLAKE2S_160 = _alg.HASH_ALGORITHM_BLAKE2S_160
    BLAKE2S_224 = _alg.HASH_ALGORITHM_BLAKE2S_224
    BLAKE3 = _alg.HASH_ALGORITHM_BLAKE3
    GOST_R3411_94 = _alg.HASH_ALGORITHM_GOST_R3411_94
    GOST_R3411_2012_256 = _alg.HASH_ALGORITHM_GOST_R3411_2012_256
    GOST_R3411_2012_512 = _alg.HASH_ALGORITHM_GOST_R3411_2012_512
    # Legacy / broken hashes retained only for interop with existing systems.
    SHA1 = _alg.HASH_ALGORITHM_SHA1
    MD5 = _alg.HASH_ALGORITHM_MD5
    OTHER = _alg.HASH_ALGORITHM_OTHER


# ── Vendor (custom) operation parameters ──────────────────────────────────────


@dataclass
class VendorParams:
    """Vendor-defined operation parameters (``CustomOperationParams``).

    Wraps a vendor namespace plus an opaque parameter payload. Provide exactly
    one of ``raw_params`` (opaque bytes) — the most common form — for
    provider-specific extensions. ``generic_params`` (a free-form JSON-like
    mapping) is also supported for structured vendor input.
    """

    vendor: str = ""
    algorithm_name: str = ""
    raw_params: bytes = b""
    generic_params: dict[str, str] | None = None

    def to_custom_proto(self) -> _params.CustomOperationParams:
        proto = _params.CustomOperationParams(
            vendor=self.vendor,
            algorithm_name=self.algorithm_name,
            raw_params=self.raw_params,
        )
        if self.generic_params:
            for key, value in self.generic_params.items():
                proto.generic_params[key] = value
        return proto


# ── Encryption parameters (EncryptRequest/DecryptRequest params oneof) ────────


@dataclass
class AeadParams:
    """AEAD parameters: additional authenticated data and optional length hint.

    ``aad`` is authenticated but not encrypted and must match on decrypt.
    ``plaintext_length`` is an optional hint used by some providers to size
    buffers; leave it ``0`` to let the provider infer it.
    """

    aad: bytes = b""
    plaintext_length: int = 0

    def to_proto(self) -> _params.AeadEncryptParams:
        return _params.AeadEncryptParams(aad=self.aad, plaintext_length=self.plaintext_length)


@dataclass
class XtsParams:
    """XTS (disk-encryption) parameters: the tweak (usually the sector index)."""

    tweak: bytes = b""

    def to_proto(self) -> _params.XtsEncryptParams:
        return _params.XtsEncryptParams(tweak=self.tweak)


@dataclass
class AsymmetricEncryptParams:
    """Asymmetric-encryption parameters: an optional OAEP label."""

    label: bytes = b""

    def to_proto(self) -> _params.AsymmetricEncryptParams:
        return _params.AsymmetricEncryptParams(label=self.label)


@dataclass
class VendorEncryptionParams:
    """Vendor-defined encryption parameters."""

    params: VendorParams = field(default_factory=VendorParams)

    def to_proto(self) -> _params.VendorEncryptionParams:
        return _params.VendorEncryptionParams(params=self.params.to_custom_proto())


# The union of parameter kinds accepted by encrypt/decrypt request builders.
EncryptionParams = AeadParams | XtsParams | AsymmetricEncryptParams | VendorEncryptionParams

# Maps each params dataclass type to the EncryptRequest/DecryptRequest oneof arm.
_ENCRYPTION_ARM: dict[type, str] = {
    AeadParams: "aead_params",
    XtsParams: "xts_params",
    AsymmetricEncryptParams: "asymmetric_params",
    VendorEncryptionParams: "vendor_params",
}


def encryption_params_arm(params: EncryptionParams) -> tuple[str, object]:
    """Return ``(oneof_arm, proto_message)`` for an encryption params value."""
    arm = _ENCRYPTION_ARM.get(type(params))
    if arm is None:
        raise ValueError(f"unsupported encryption params: {type(params).__name__}")
    return arm, params.to_proto()


# ── Signature contexts (SignRequest/VerifyRequest context oneof) ──────────────


@dataclass
class DomainContext:
    """Signature domain-separation context (e.g. Ed25519ctx / prehash context)."""

    context: bytes = b""

    def to_proto(self) -> _params.SignatureDomainContext:
        return _params.SignatureDomainContext(context=self.context)


@dataclass
class VendorSignatureContext:
    """Vendor-defined signature context."""

    params: VendorParams = field(default_factory=VendorParams)

    def to_proto(self) -> _params.VendorSignatureContext:
        return _params.VendorSignatureContext(params=self.params.to_custom_proto())


# The union of context kinds accepted by sign/verify request builders.
SignatureContext = DomainContext | VendorSignatureContext

# Maps each context dataclass type to the Sign/Verify request oneof arm.
_SIGNATURE_ARM: dict[type, str] = {
    DomainContext: "domain_context",
    VendorSignatureContext: "vendor_context",
}


def signature_context_arm(context: SignatureContext) -> tuple[str, object]:
    """Return ``(oneof_arm, proto_message)`` for a signature context value."""
    arm = _SIGNATURE_ARM.get(type(context))
    if arm is None:
        raise ValueError(f"unsupported signature context: {type(context).__name__}")
    return arm, context.to_proto()
