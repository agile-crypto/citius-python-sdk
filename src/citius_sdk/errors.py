"""Normalized error hierarchy for Citius service clients."""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import ParamSpec, TypeVar

import grpc


class CitiusError(Exception):
    """Base error carrying the gRPC status code and safe message."""

    def __init__(self, code: grpc.StatusCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code.name.lower()}: {self.message}"


class AuthenticationError(CitiusError):
    """Raised when credentials are missing, invalid, or expired."""


class PermissionDeniedError(CitiusError):
    """Raised when the identity lacks the required method or resource permission."""


class NotFoundError(CitiusError):
    """Raised when a requested resource does not exist."""


class InvalidArgumentError(CitiusError):
    """Raised when the request is structurally invalid."""


class FailedPreconditionError(CitiusError):
    """Raised when a lifecycle or policy precondition is not met."""


class UnimplementedError(CitiusError):
    """Raised when the connected server does not implement the RPC."""


class DeadlineExceededError(CitiusError):
    """Raised when the per-call deadline elapses."""


class UnavailableError(CitiusError):
    """Raised on connectivity, TLS, or transport failures."""


class AlreadyExistsError(CitiusError):
    """Raised when a resource already exists."""


_CODE_TO_ERROR: dict[grpc.StatusCode, type[CitiusError]] = {
    grpc.StatusCode.UNAUTHENTICATED: AuthenticationError,
    grpc.StatusCode.PERMISSION_DENIED: PermissionDeniedError,
    grpc.StatusCode.NOT_FOUND: NotFoundError,
    grpc.StatusCode.INVALID_ARGUMENT: InvalidArgumentError,
    grpc.StatusCode.FAILED_PRECONDITION: FailedPreconditionError,
    grpc.StatusCode.UNIMPLEMENTED: UnimplementedError,
    grpc.StatusCode.DEADLINE_EXCEEDED: DeadlineExceededError,
    grpc.StatusCode.UNAVAILABLE: UnavailableError,
    grpc.StatusCode.ALREADY_EXISTS: AlreadyExistsError,
}


def from_rpc_error(error: grpc.aio.AioRpcError) -> CitiusError:
    """Map a gRPC failure to the matching Citius error subclass."""
    code = error.code()
    error_type = _CODE_TO_ERROR.get(code, CitiusError)
    return error_type(code, error.details() or code.name)


P = ParamSpec("P")
T = TypeVar("T")


def map_rpc_errors(fn: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
    """Convert raw gRPC failures raised by an async method into Citius errors."""

    @functools.wraps(fn)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return await fn(*args, **kwargs)
        except grpc.aio.AioRpcError as error:
            raise from_rpc_error(error) from error

    return wrapper
