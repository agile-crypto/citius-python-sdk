"""Unit tests for the intent-oriented request vocabulary."""

from __future__ import annotations

import pytest
from citius_api.types import common_pb2 as common

from citius_sdk import (
    AeadProperties,
    Fips140Level,
    KdfProperties,
    KeyAgreementProperties,
    NistSecurityLevel,
    NistStatus,
    Primitive,
    ProviderRequirements,
    Scope,
    SecurityProperties,
    SignatureProperties,
    build_scope_spec,
)
from citius_sdk.services.key_management import create_key_request

# ── Scope table ────────────────────────────────────────────────────────────────


def test_every_scope_has_a_mapping() -> None:
    for scope in Scope:
        assert scope.primitive is not Primitive.UNKNOWN
        assert scope.spec_arm
        assert isinstance(scope.to_proto_value(), int)


@pytest.mark.parametrize(
    ("scope", "arm", "value"),
    [
        (Scope.SIGNATURE_STANDARD, "signature", common.SIGNATURE_SCOPE_STANDARD),
        (Scope.SIGNATURE_PREHASHED, "signature", common.SIGNATURE_SCOPE_PREHASHED),
        (Scope.AEAD_STANDARD, "aead", common.AEAD_SCOPE_STANDARD),
        (Scope.AEAD_DETERMINISTIC, "aead", common.AEAD_SCOPE_DETERMINISTIC),
        (Scope.MAC_STANDARD, "mac", common.MAC_SCOPE_STANDARD),
        (Scope.KEM_HYBRID, "kem", common.KEM_SCOPE_HYBRID),
        (Scope.KEY_AGREEMENT_HYBRID, "key_agreement", common.KEY_AGREEMENT_SCOPE_HYBRID),
        (Scope.KDF_PASSWORD, "kdf", common.KDF_SCOPE_PASSWORD),
        (Scope.HASH_XOF, "hash", common.HASH_SCOPE_XOF),
        (Scope.KEY_WRAPPING_WITH_PADDING, "key_wrapping", common.KEY_WRAPPING_SCOPE_WITH_PADDING),
        (Scope.SYMMETRIC_CIPHER_BLOCK, "symmetric_cipher", common.SYMMETRIC_CIPHER_SCOPE_BLOCK),
        (Scope.DISK_ENCRYPTION_STANDARD, "disk_encryption", common.DISK_ENCRYPTION_SCOPE_STANDARD),
        (Scope.GENERIC_SECRET_STANDARD, "generic_secret", common.GENERIC_SECRET_SCOPE_STANDARD),
        (
            Scope.ASYMMETRIC_ENCRYPTION_RAW,
            "asymmetric_encryption",
            common.ASYMMETRIC_ENCRYPTION_SCOPE_RAW,
        ),
    ],
)
def test_scope_maps_to_arm_and_value(scope: Scope, arm: str, value: int) -> None:
    assert scope.spec_arm == arm
    assert scope.to_proto_value() == value


# ── build_scope_spec ────────────────────────────────────────────────────────────


def test_build_scope_spec_sets_correct_arm() -> None:
    spec = build_scope_spec(Scope.AEAD_STANDARD)
    assert spec.WhichOneof("scope_spec") == "aead"
    assert spec.aead.scope == common.AEAD_SCOPE_STANDARD


def test_build_scope_spec_with_security_properties() -> None:
    spec = build_scope_spec(
        Scope.SIGNATURE_STANDARD,
        security=SecurityProperties(
            security_strength_bits=256,
            nist_security_level=NistSecurityLevel.LEVEL_3,
            quantum_safe=True,
            nist_status=NistStatus.APPROVED,
            fips_approved=True,
        ),
    )
    sig = spec.signature
    assert sig.security.security_strength_bits == 256
    assert sig.security.nist_security_level == common.NIST_SECURITY_LEVEL_3
    assert sig.security.nist_status == common.NIST_STATUS_APPROVED
    assert sig.security.HasField("quantum_safe") and sig.security.quantum_safe is True
    assert sig.security.HasField("fips_approved") and sig.security.fips_approved is True


def test_security_optional_bools_absent_when_unset() -> None:
    spec = build_scope_spec(
        Scope.SIGNATURE_STANDARD, security=SecurityProperties(security_strength_bits=128)
    )
    assert not spec.signature.security.HasField("quantum_safe")
    assert not spec.signature.security.HasField("fips_approved")


def test_build_scope_spec_signature_primitive_properties() -> None:
    spec = build_scope_spec(
        Scope.SIGNATURE_STANDARD,
        primitive=SignatureProperties(non_malleable=True, deterministic=True),
    )
    assert spec.signature.HasField("non_malleable") and spec.signature.non_malleable is True
    assert spec.signature.HasField("deterministic") and spec.signature.deterministic is True


def test_build_scope_spec_aead_primitive_properties() -> None:
    spec = build_scope_spec(
        Scope.AEAD_STANDARD, primitive=AeadProperties(nonce_misuse_resistant=True)
    )
    assert spec.aead.HasField("nonce_misuse_resistant") and spec.aead.nonce_misuse_resistant is True


def test_build_scope_spec_key_agreement_and_kdf_properties() -> None:
    ka = build_scope_spec(
        Scope.KEY_AGREEMENT_STANDARD, primitive=KeyAgreementProperties(forward_secrecy=True)
    )
    assert ka.key_agreement.forward_secrecy is True
    kdf = build_scope_spec(Scope.KDF_PASSWORD, primitive=KdfProperties(memory_hard=True))
    assert kdf.kdf.memory_hard is True


def test_build_scope_spec_additional_properties() -> None:
    spec = build_scope_spec(Scope.HASH_STANDARD, additional={"vendor": "acme"})
    assert dict(spec.hash.additional_properties) == {"vendor": "acme"}


def test_primitive_property_mismatch_raises() -> None:
    with pytest.raises(ValueError, match="do not match"):
        build_scope_spec(Scope.AEAD_STANDARD, primitive=SignatureProperties(non_malleable=True))


# ── ProviderRequirements ─────────────────────────────────────────────────────────


def test_provider_requirements_to_proto() -> None:
    proto = ProviderRequirements(
        fips_140_certified=True,
        min_fips_level=Fips140Level.LEVEL_2,
        common_criteria_certified=True,
        formally_verified=True,
        memory_safe=True,
        constant_time=True,
        side_channel_hardened=True,
        no_known_cve=True,
        prefer_hardware_accelerated=True,
        additional_properties={"region": "eu"},
    ).to_proto()
    assert proto.fips_140_certified is True
    assert proto.min_fips_level == Fips140Level.LEVEL_2
    assert proto.memory_safe is True
    assert proto.constant_time is True
    assert dict(proto.additional) == {"region": "eu"}


# ── create_key_request wiring ────────────────────────────────────────────────────


def test_create_key_request_builds_scope_spec_and_provider_requirements() -> None:
    request = create_key_request(
        "demo-key",
        policy="demo-policy",
        scope=Scope.AEAD_STANDARD,
        primitive_properties=AeadProperties(nonce_misuse_resistant=True),
        provider_requirements=ProviderRequirements(constant_time=True),
        provider_configuration={"slot": "0"},
    )
    assert request.name == "demo-key"
    assert request.policy == "demo-policy"
    assert request.scope_spec.WhichOneof("scope_spec") == "aead"
    assert request.scope_spec.aead.scope == common.AEAD_SCOPE_STANDARD
    assert request.scope_spec.aead.nonce_misuse_resistant is True
    assert request.provider_requirements.constant_time is True
    assert dict(request.provider_configuration) == {"slot": "0"}


def test_create_key_request_template_only_still_supported() -> None:
    request = create_key_request("demo-key", template_id="aes-256-gcm-96")
    assert request.template_id == "aes-256-gcm-96"
    assert request.WhichOneof is not None  # sanity
    assert not request.HasField("scope_spec")


def test_create_key_request_requires_scope_or_template() -> None:
    with pytest.raises(Exception, match="scope or template_id"):
        create_key_request("demo-key")


def test_create_key_request_filter_without_scope_rejected() -> None:
    with pytest.raises(Exception, match="require a scope"):
        create_key_request(
            "demo-key",
            template_id="tmpl",
            security_properties=SecurityProperties(security_strength_bits=128),
        )


def test_create_key_request_primitive_mismatch_rejected() -> None:
    with pytest.raises(Exception, match="do not match"):
        create_key_request(
            "demo-key",
            scope=Scope.AEAD_STANDARD,
            primitive_properties=SignatureProperties(deterministic=True),
        )
