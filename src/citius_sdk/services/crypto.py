"""Cryptographic operations service client."""

from __future__ import annotations

import grpc
from citius_api.messages.encryption_pb2 import (
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
)
from citius_api.messages.metadata_pb2 import OperationMetadata as OperationMetadataProto
from citius_api.messages.signing_pb2 import (
    DigestSignRequest,
    DigestSignResponse,
    DigestVerifyRequest,
    DigestVerifyResponse,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)
from citius_api.services.crypto_service_pb2_grpc import CryptoServiceStub

from citius_sdk.auth import TokenProvider
from citius_sdk.channel import create_channel
from citius_sdk.config import ClientConfig
from citius_sdk.errors import InvalidArgumentError, map_rpc_errors
from citius_sdk.metadata import OperationMetadata, metadata_from_proto
from citius_sdk.params import (
    EncryptionParams,
    HashAlgorithm,
    SignatureContext,
    encryption_params_arm,
    signature_context_arm,
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


def _set_encryption_params(
    request: EncryptRequest | DecryptRequest, params: EncryptionParams
) -> None:
    arm, proto = encryption_params_arm(params)
    getattr(request, arm).CopyFrom(proto)


def encrypt_request(
    key_name: str,
    plaintext: bytes,
    *,
    params: EncryptionParams | None = None,
    user_context: dict[str, str] | None = None,
) -> EncryptRequest:
    """Build an EncryptRequest, optionally with operation ``params``.

    ``params`` selects a parameter kind (e.g. :class:`AeadParams` to attach
    additional authenticated data). When omitted, the request uses the default
    (server-selected) parameters for the key's scope. ``user_context`` is an
    opaque string map echoed back in the operation metadata.
    """
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(plaintext), "plaintext is empty")
    _raise_if_invalid("encrypt request", errors)
    request = EncryptRequest(key_name=key_name, plaintext=plaintext)
    if params is not None:
        try:
            _set_encryption_params(request, params)
        except ValueError as exc:
            raise InvalidArgumentError(
                grpc.StatusCode.INVALID_ARGUMENT, f"invalid encrypt request: {exc}"
            ) from exc
    if user_context:
        request.user_context.update(user_context)
    return request


def decrypt_request(
    key_name: str,
    ciphertext: bytes,
    metadata: OperationMetadataProto,
    *,
    params: EncryptionParams | None = None,
    user_context: dict[str, str] | None = None,
) -> DecryptRequest:
    """Build a DecryptRequest carrying the ciphertext operation metadata.

    ``params`` must match the parameters used at encrypt time (e.g. the same
    :class:`AeadParams` AAD) or verification/decryption fails.
    """
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(ciphertext), "ciphertext is empty")
    _require(errors, metadata is not None, "metadata is required")
    _raise_if_invalid("decrypt request", errors)
    request = DecryptRequest(key_name=key_name, ciphertext=ciphertext, metadata=metadata)
    if params is not None:
        try:
            _set_encryption_params(request, params)
        except ValueError as exc:
            raise InvalidArgumentError(
                grpc.StatusCode.INVALID_ARGUMENT, f"invalid decrypt request: {exc}"
            ) from exc
    if user_context:
        request.user_context.update(user_context)
    return request


def _set_signature_context(
    request: SignRequest | VerifyRequest | DigestSignRequest | DigestVerifyRequest,
    context: SignatureContext,
) -> None:
    arm, proto = signature_context_arm(context)
    getattr(request, arm).CopyFrom(proto)


def sign_request(
    key_name: str,
    message: bytes,
    *,
    context: SignatureContext | None = None,
    user_context: dict[str, str] | None = None,
) -> SignRequest:
    """Build a SignRequest, optionally with a signature ``context``.

    ``context`` selects a domain-separation or vendor context (e.g.
    :class:`DomainContext` for Ed25519ctx). When omitted the signature uses no
    context. ``user_context`` is an opaque string map echoed in the metadata.
    """
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(message), "input is empty")
    _raise_if_invalid("sign request", errors)
    request = SignRequest(key_name=key_name, input=message)
    if context is not None:
        try:
            _set_signature_context(request, context)
        except ValueError as exc:
            raise InvalidArgumentError(
                grpc.StatusCode.INVALID_ARGUMENT, f"invalid sign request: {exc}"
            ) from exc
    if user_context:
        request.user_context.update(user_context)
    return request


def verify_request(
    key_name: str,
    message: bytes,
    signature: bytes,
    metadata: OperationMetadataProto,
    *,
    context: SignatureContext | None = None,
    user_context: dict[str, str] | None = None,
) -> VerifyRequest:
    """Build a VerifyRequest carrying the signature operation metadata.

    ``context`` must match the context used at sign time or verification fails.
    """
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(message), "input is empty")
    _require(errors, bool(signature), "signature is empty")
    _require(errors, metadata is not None, "metadata is required")
    _raise_if_invalid("verify request", errors)
    request = VerifyRequest(
        key_name=key_name, input=message, signature=signature, metadata=metadata
    )
    if context is not None:
        try:
            _set_signature_context(request, context)
        except ValueError as exc:
            raise InvalidArgumentError(
                grpc.StatusCode.INVALID_ARGUMENT, f"invalid verify request: {exc}"
            ) from exc
    if user_context:
        request.user_context.update(user_context)
    return request


def digest_sign_request(
    key_name: str,
    digest: bytes,
    *,
    context: SignatureContext | None = None,
    hash_algorithm: HashAlgorithm | None = None,
    hash_algorithm_oid: str = "",
    user_context: dict[str, str] | None = None,
) -> DigestSignRequest:
    """Build a DigestSignRequest for a pre-computed ``digest``.

    ``hash_algorithm`` (or ``hash_algorithm_oid``) declares which hash produced
    the digest so the provider can build the correct signature encoding.
    """
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(digest), "digest is empty")
    _raise_if_invalid("digest sign request", errors)
    request = DigestSignRequest(key_name=key_name, digest=digest)
    if context is not None:
        try:
            _set_signature_context(request, context)
        except ValueError as exc:
            raise InvalidArgumentError(
                grpc.StatusCode.INVALID_ARGUMENT, f"invalid digest sign request: {exc}"
            ) from exc
    if hash_algorithm is not None:
        request.hash_algorithm = int(hash_algorithm)
    if hash_algorithm_oid:
        request.hash_algorithm_oid = hash_algorithm_oid
    if user_context:
        request.user_context.update(user_context)
    return request


def digest_verify_request(
    key_name: str,
    digest: bytes,
    signature: bytes,
    metadata: OperationMetadataProto,
    *,
    context: SignatureContext | None = None,
    hash_algorithm: HashAlgorithm | None = None,
    hash_algorithm_oid: str = "",
    user_context: dict[str, str] | None = None,
) -> DigestVerifyRequest:
    """Build a DigestVerifyRequest carrying the signature operation metadata."""
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(digest), "digest is empty")
    _require(errors, bool(signature), "signature is empty")
    _require(errors, metadata is not None, "metadata is required")
    _raise_if_invalid("digest verify request", errors)
    request = DigestVerifyRequest(
        key_name=key_name, digest=digest, signature=signature, metadata=metadata
    )
    if context is not None:
        try:
            _set_signature_context(request, context)
        except ValueError as exc:
            raise InvalidArgumentError(
                grpc.StatusCode.INVALID_ARGUMENT, f"invalid digest verify request: {exc}"
            ) from exc
    if hash_algorithm is not None:
        request.hash_algorithm = int(hash_algorithm)
    if hash_algorithm_oid:
        request.hash_algorithm_oid = hash_algorithm_oid
    if user_context:
        request.user_context.update(user_context)
    return request


class EncryptResult:
    """Ciphertext and lossless operation metadata from an encryption."""

    def __init__(self, inner: EncryptResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> EncryptResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def ciphertext(self) -> bytes:
        return self._inner.ciphertext

    @property
    def metadata(self) -> OperationMetadata | None:
        return metadata_from_proto(
            self._inner.metadata if self._inner.HasField("metadata") else None
        )


class DecryptResult:
    """Plaintext and lossless operation metadata from a decryption."""

    def __init__(self, inner: DecryptResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> DecryptResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def plaintext(self) -> bytes:
        return self._inner.plaintext

    @property
    def metadata(self) -> OperationMetadata | None:
        return metadata_from_proto(
            self._inner.metadata if self._inner.HasField("metadata") else None
        )


class SignResult:
    """Signature and lossless operation metadata from a signing operation."""

    def __init__(self, inner: SignResponse | DigestSignResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> SignResponse | DigestSignResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def signature(self) -> bytes:
        return self._inner.signature

    @property
    def metadata(self) -> OperationMetadata | None:
        return metadata_from_proto(
            self._inner.metadata if self._inner.HasField("metadata") else None
        )


class VerifyResult:
    """Verification outcome and lossless operation metadata."""

    def __init__(self, inner: VerifyResponse | DigestVerifyResponse) -> None:
        self._inner = inner

    @property
    def proto(self) -> VerifyResponse | DigestVerifyResponse:
        """The full underlying response message."""
        return self._inner

    @property
    def valid(self) -> bool:
        return self._inner.valid

    @property
    def metadata(self) -> OperationMetadata | None:
        return metadata_from_proto(
            self._inner.metadata if self._inner.HasField("metadata") else None
        )


class CryptoClient:
    """Async client for cryptographic operations."""

    def __init__(
        self,
        channel: grpc.aio.Channel,
        *,
        timeout: float,
        close_channel: bool = False,
    ) -> None:
        self._channel = channel
        self._stub = CryptoServiceStub(channel)
        self._timeout = timeout
        self._close_channel = close_channel

    @classmethod
    def connect(
        cls,
        config: ClientConfig,
        *,
        token_provider: TokenProvider | None = None,
    ) -> CryptoClient:
        """Create a crypto client that owns its configured channel."""
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
    async def encrypt(
        self, request: EncryptRequest, *, timeout: float | None = None
    ) -> EncryptResult:
        response = await self._stub.Encrypt(request, timeout=self._deadline(timeout))
        return EncryptResult(response)

    @map_rpc_errors
    async def decrypt(
        self, request: DecryptRequest, *, timeout: float | None = None
    ) -> DecryptResult:
        response = await self._stub.Decrypt(request, timeout=self._deadline(timeout))
        return DecryptResult(response)

    @map_rpc_errors
    async def sign(self, request: SignRequest, *, timeout: float | None = None) -> SignResult:
        response = await self._stub.Sign(request, timeout=self._deadline(timeout))
        return SignResult(response)

    @map_rpc_errors
    async def verify(self, request: VerifyRequest, *, timeout: float | None = None) -> VerifyResult:
        response = await self._stub.Verify(request, timeout=self._deadline(timeout))
        return VerifyResult(response)

    @map_rpc_errors
    async def digest_sign(
        self, request: DigestSignRequest, *, timeout: float | None = None
    ) -> SignResult:
        response = await self._stub.DigestSign(request, timeout=self._deadline(timeout))
        return SignResult(response)

    @map_rpc_errors
    async def digest_verify(
        self, request: DigestVerifyRequest, *, timeout: float | None = None
    ) -> VerifyResult:
        response = await self._stub.DigestVerify(request, timeout=self._deadline(timeout))
        return VerifyResult(response)

    async def close(self, grace: float | None = None) -> None:
        """Close the channel when this client created it."""
        if self._close_channel:
            await self._channel.close(grace)

    async def __aenter__(self) -> CryptoClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()
