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


def _require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def _raise_if_invalid(request_type: str, errors: list[str]) -> None:
    if errors:
        raise InvalidArgumentError(
            grpc.StatusCode.INVALID_ARGUMENT,
            f"invalid {request_type}: {'; '.join(errors)}",
        )


def encrypt_request(key_name: str, plaintext: bytes) -> EncryptRequest:
    """Build an EncryptRequest with no scope-specific parameters."""
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(plaintext), "plaintext is empty")
    _raise_if_invalid("encrypt request", errors)
    return EncryptRequest(key_name=key_name, plaintext=plaintext)


def decrypt_request(
    key_name: str, ciphertext: bytes, metadata: OperationMetadataProto
) -> DecryptRequest:
    """Build a DecryptRequest carrying the ciphertext operation metadata."""
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(ciphertext), "ciphertext is empty")
    _require(errors, metadata is not None, "metadata is required")
    _raise_if_invalid("decrypt request", errors)
    return DecryptRequest(key_name=key_name, ciphertext=ciphertext, metadata=metadata)


def sign_request(key_name: str, message: bytes) -> SignRequest:
    """Build a SignRequest with no signature context."""
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(message), "input is empty")
    _raise_if_invalid("sign request", errors)
    return SignRequest(key_name=key_name, input=message)


def verify_request(
    key_name: str, message: bytes, signature: bytes, metadata: OperationMetadataProto
) -> VerifyRequest:
    """Build a VerifyRequest carrying the signature operation metadata."""
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(message), "input is empty")
    _require(errors, bool(signature), "signature is empty")
    _require(errors, metadata is not None, "metadata is required")
    _raise_if_invalid("verify request", errors)
    return VerifyRequest(key_name=key_name, input=message, signature=signature, metadata=metadata)


def digest_sign_request(key_name: str, digest: bytes) -> DigestSignRequest:
    """Build a DigestSignRequest with no signature context."""
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(digest), "digest is empty")
    _raise_if_invalid("digest sign request", errors)
    return DigestSignRequest(key_name=key_name, digest=digest)


def digest_verify_request(
    key_name: str, digest: bytes, signature: bytes, metadata: OperationMetadataProto
) -> DigestVerifyRequest:
    """Build a DigestVerifyRequest carrying the signature operation metadata."""
    errors: list[str] = []
    _require(errors, bool(key_name), "key name is empty")
    _require(errors, bool(digest), "digest is empty")
    _require(errors, bool(signature), "signature is empty")
    _require(errors, metadata is not None, "metadata is required")
    _raise_if_invalid("digest verify request", errors)
    return DigestVerifyRequest(
        key_name=key_name, digest=digest, signature=signature, metadata=metadata
    )


class EncryptResult:
    """Ciphertext and lossless operation metadata from an encryption."""

    def __init__(self, inner: EncryptResponse) -> None:
        self._inner = inner

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
