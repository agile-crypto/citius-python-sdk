from __future__ import annotations

import grpc
import pytest

from citius_sdk.errors import (
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
    map_rpc_errors,
)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (grpc.StatusCode.UNAUTHENTICATED, AuthenticationError),
        (grpc.StatusCode.PERMISSION_DENIED, PermissionDeniedError),
        (grpc.StatusCode.NOT_FOUND, NotFoundError),
        (grpc.StatusCode.INVALID_ARGUMENT, InvalidArgumentError),
        (grpc.StatusCode.FAILED_PRECONDITION, FailedPreconditionError),
        (grpc.StatusCode.UNIMPLEMENTED, UnimplementedError),
        (grpc.StatusCode.DEADLINE_EXCEEDED, DeadlineExceededError),
        (grpc.StatusCode.UNAVAILABLE, UnavailableError),
        (grpc.StatusCode.INTERNAL, CitiusError),
    ],
)
def test_from_rpc_error_maps_status_codes(code, expected) -> None:
    rpc_error = grpc.aio.AioRpcError(code, None, None, details="failure detail")
    error = from_rpc_error(rpc_error)
    assert type(error) is expected
    assert error.code is code
    assert error.message == "failure detail"


def test_from_rpc_error_falls_back_to_code_name_without_details() -> None:
    rpc_error = grpc.aio.AioRpcError(grpc.StatusCode.NOT_FOUND, None, None)
    error = from_rpc_error(rpc_error)
    assert error.message == grpc.StatusCode.NOT_FOUND.name


def test_error_str_does_not_leak_credentials() -> None:
    error = CitiusError(grpc.StatusCode.PERMISSION_DENIED, "denied for demo-restricted-key")
    text = str(error)
    assert "Bearer" not in text
    assert "authorization" not in text.lower()


@pytest.mark.asyncio
async def test_map_rpc_errors_converts_aio_rpc_error() -> None:
    @map_rpc_errors
    async def call() -> None:
        raise grpc.aio.AioRpcError(grpc.StatusCode.PERMISSION_DENIED, None, None, details="denied")

    with pytest.raises(PermissionDeniedError):
        await call()


@pytest.mark.asyncio
async def test_map_rpc_errors_passes_through_success() -> None:
    @map_rpc_errors
    async def call() -> int:
        return 7

    assert await call() == 7
