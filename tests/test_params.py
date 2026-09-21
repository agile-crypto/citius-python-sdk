from __future__ import annotations

import pytest

from citius_sdk import (
    AeadParams,
    AsymmetricEncryptParams,
    DomainContext,
    HashAlgorithm,
    VendorEncryptionParams,
    VendorParams,
    VendorSignatureContext,
    XtsParams,
)
from citius_sdk.errors import InvalidArgumentError
from citius_sdk.params import encryption_params_arm, signature_context_arm
from citius_sdk.services.crypto import (
    decrypt_request,
    digest_sign_request,
    digest_verify_request,
    encrypt_request,
    sign_request,
    verify_request,
)


def _metadata():
    from citius_api.messages.metadata_pb2 import OperationMetadata

    md = OperationMetadata()
    md.key_version = 1
    return md


# ── params/context arm mapping ────────────────────────────────────────────────


def test_encryption_params_arm_mapping() -> None:
    assert encryption_params_arm(AeadParams(aad=b"a"))[0] == "aead_params"
    assert encryption_params_arm(XtsParams(tweak=b"t"))[0] == "xts_params"
    assert encryption_params_arm(AsymmetricEncryptParams(label=b"l"))[0] == "asymmetric_params"
    assert encryption_params_arm(VendorEncryptionParams())[0] == "vendor_params"


def test_signature_context_arm_mapping() -> None:
    assert signature_context_arm(DomainContext(context=b"c"))[0] == "domain_context"
    assert signature_context_arm(VendorSignatureContext())[0] == "vendor_context"


# ── encrypt/decrypt params wiring ─────────────────────────────────────────────


def test_encrypt_request_sets_aead_params() -> None:
    request = encrypt_request("k", b"pt", params=AeadParams(aad=b"header", plaintext_length=2))
    assert request.WhichOneof("scope_params") == "aead_params"
    assert request.aead_params.aad == b"header"
    assert request.aead_params.plaintext_length == 2


def test_encrypt_request_sets_user_context() -> None:
    request = encrypt_request("k", b"pt", user_context={"trace": "abc"})
    assert dict(request.user_context) == {"trace": "abc"}


def test_encrypt_request_default_has_no_params() -> None:
    request = encrypt_request("k", b"pt")
    assert request.WhichOneof("scope_params") is None


def test_decrypt_request_sets_xts_params() -> None:
    request = decrypt_request("k", b"ct", _metadata(), params=XtsParams(tweak=b"sector0"))
    assert request.WhichOneof("scope_params") == "xts_params"
    assert request.xts_params.tweak == b"sector0"


def test_decrypt_request_sets_asymmetric_label() -> None:
    request = decrypt_request(
        "k", b"ct", _metadata(), params=AsymmetricEncryptParams(label=b"oaep")
    )
    assert request.WhichOneof("scope_params") == "asymmetric_params"
    assert request.asymmetric_params.label == b"oaep"


def test_vendor_encryption_params_carry_custom_payload() -> None:
    request = encrypt_request(
        "k",
        b"pt",
        params=VendorEncryptionParams(
            VendorParams(vendor="acme", algorithm_name="x", raw_params=b"raw")
        ),
    )
    assert request.WhichOneof("scope_params") == "vendor_params"
    assert request.vendor_params.params.vendor == "acme"
    assert request.vendor_params.params.raw_params == b"raw"


# ── sign/verify context wiring ────────────────────────────────────────────────


def test_sign_request_sets_domain_context() -> None:
    request = sign_request("k", b"msg", context=DomainContext(context=b"dom"))
    assert request.WhichOneof("scope_params") == "domain_context"
    assert request.domain_context.context == b"dom"


def test_sign_request_default_has_no_context() -> None:
    request = sign_request("k", b"msg")
    assert request.WhichOneof("scope_params") is None


def test_verify_request_sets_vendor_context_and_user_context() -> None:
    request = verify_request(
        "k",
        b"msg",
        b"sig",
        _metadata(),
        context=VendorSignatureContext(VendorParams(vendor="acme")),
        user_context={"k": "v"},
    )
    assert request.WhichOneof("scope_params") == "vendor_context"
    assert request.vendor_context.params.vendor == "acme"
    assert dict(request.user_context) == {"k": "v"}


# ── digest sign/verify hash algorithm ─────────────────────────────────────────


def test_digest_sign_request_sets_hash_algorithm() -> None:
    request = digest_sign_request("k", b"digest", hash_algorithm=HashAlgorithm.SHA256)
    assert request.hash_algorithm == int(HashAlgorithm.SHA256)


def test_digest_sign_request_sets_hash_oid() -> None:
    request = digest_sign_request("k", b"digest", hash_algorithm_oid="2.16.840.1.101.3.4.2.1")
    assert request.hash_algorithm_oid == "2.16.840.1.101.3.4.2.1"


def test_digest_verify_request_sets_hash_algorithm_and_context() -> None:
    request = digest_verify_request(
        "k",
        b"digest",
        b"sig",
        _metadata(),
        context=DomainContext(context=b"dom"),
        hash_algorithm=HashAlgorithm.SHA384,
    )
    assert request.hash_algorithm == int(HashAlgorithm.SHA384)
    assert request.WhichOneof("scope_params") == "domain_context"


# ── validation still holds ────────────────────────────────────────────────────


def test_encrypt_request_requires_plaintext() -> None:
    with pytest.raises(InvalidArgumentError):
        encrypt_request("k", b"", params=AeadParams(aad=b"a"))


def test_sign_request_requires_key_name() -> None:
    with pytest.raises(InvalidArgumentError):
        sign_request("", b"msg", context=DomainContext(context=b"c"))
