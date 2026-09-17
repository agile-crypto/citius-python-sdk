from __future__ import annotations

import grpc
import pytest
import pytest_asyncio
from citius_api.messages.encryption_pb2 import DecryptResponse, EncryptResponse
from citius_api.messages.signing_pb2 import (
    DigestSignResponse,
    DigestVerifyResponse,
    SignResponse,
    VerifyResponse,
)
from citius_api.services.crypto_service_pb2_grpc import (
    CryptoServiceServicer,
    add_CryptoServiceServicer_to_server,
)

from citius_sdk import ClientConfig, StaticTokenProvider, TLSConfig
from citius_sdk.errors import AuthenticationError, InvalidArgumentError, PermissionDeniedError
from citius_sdk.services.crypto import (
    CryptoClient,
    decrypt_request,
    digest_sign_request,
    digest_verify_request,
    encrypt_request,
    sign_request,
    verify_request,
)

_DENIED_KEY = "demo-restricted-key"


class FakeCryptoService(CryptoServiceServicer):
    async def _guard(self, context) -> None:
        metadata = dict(context.invocation_metadata())
        if metadata.get("authorization") is None:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "bearer token required")

    async def Encrypt(self, request, context):  # noqa: N802
        await self._guard(context)
        if request.key_name == _DENIED_KEY:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "denied")
        response = EncryptResponse(ciphertext=b"ct:" + request.plaintext)
        response.metadata.key_version = 7
        response.metadata.api_version = "v1"
        return response

    async def Decrypt(self, request, context):  # noqa: N802
        await self._guard(context)
        return DecryptResponse(plaintext=request.ciphertext.removeprefix(b"ct:"))

    async def Sign(self, request, context):  # noqa: N802
        await self._guard(context)
        response = SignResponse(signature=b"sig:" + request.input)
        response.metadata.key_version = 5
        response.metadata.api_version = "v1"
        return response

    async def Verify(self, request, context):  # noqa: N802
        await self._guard(context)
        valid = request.signature == b"sig:" + request.input and request.metadata.key_version == 5
        return VerifyResponse(valid=valid)

    async def DigestSign(self, request, context):  # noqa: N802
        await self._guard(context)
        response = DigestSignResponse(signature=b"dsig:" + request.digest)
        response.metadata.key_version = 9
        return response

    async def DigestVerify(self, request, context):  # noqa: N802
        await self._guard(context)
        return DigestVerifyResponse(valid=request.signature == b"dsig:" + request.digest)


@pytest_asyncio.fixture
async def crypto_endpoint():
    server = grpc.aio.server()
    add_CryptoServiceServicer_to_server(FakeCryptoService(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield f"127.0.0.1:{port}"
    finally:
        await server.stop(grace=None)


def _config(endpoint: str) -> ClientConfig:
    return ClientConfig(endpoint=endpoint, tls=TLSConfig(enabled=False))


@pytest.mark.asyncio
async def test_encrypt_decrypt_round_trip(crypto_endpoint) -> None:
    async with CryptoClient.connect(
        _config(crypto_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        encrypted = await client.encrypt(encrypt_request("demo-key", b"secret"))
        assert encrypted.metadata is not None
        assert encrypted.metadata.key_version == 7
        decrypted = await client.decrypt(
            decrypt_request("demo-key", encrypted.ciphertext, encrypted.metadata.proto)
        )
    assert decrypted.plaintext == b"secret"


@pytest.mark.asyncio
async def test_sign_then_verify_uses_returned_metadata(crypto_endpoint) -> None:
    async with CryptoClient.connect(
        _config(crypto_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        signed = await client.sign(sign_request("demo-key", b"message"))
        assert signed.metadata is not None
        assert signed.metadata.key_version == 5
        verified = await client.verify(
            verify_request("demo-key", b"message", signed.signature, signed.metadata.proto)
        )
    assert verified.valid is True


@pytest.mark.asyncio
async def test_digest_sign_then_digest_verify(crypto_endpoint) -> None:
    async with CryptoClient.connect(
        _config(crypto_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        signed = await client.digest_sign(digest_sign_request("demo-key", b"digest"))
        verified = await client.digest_verify(
            digest_verify_request("demo-key", b"digest", signed.signature, signed.metadata.proto)
        )
    assert verified.valid is True


@pytest.mark.asyncio
async def test_missing_token_raises_authentication_error(crypto_endpoint) -> None:
    async with CryptoClient.connect(_config(crypto_endpoint)) as client:
        with pytest.raises(AuthenticationError):
            await client.encrypt(encrypt_request("demo-key", b"secret"))


@pytest.mark.asyncio
async def test_denied_key_raises_permission_denied(crypto_endpoint) -> None:
    async with CryptoClient.connect(
        _config(crypto_endpoint), token_provider=StaticTokenProvider("t")
    ) as client:
        with pytest.raises(PermissionDeniedError):
            await client.encrypt(encrypt_request(_DENIED_KEY, b"secret"))


def test_request_builders_report_all_validation_errors() -> None:
    with pytest.raises(InvalidArgumentError) as raised:
        encrypt_request("", b"")
    assert "key name is empty" in str(raised.value)
    assert "plaintext is empty" in str(raised.value)
