"""Lossless wrapper around the generated OperationMetadata message."""

from __future__ import annotations

from citius_api.messages.metadata_pb2 import OperationMetadata as OperationMetadataProto
from google.protobuf.json_format import MessageToDict


class OperationMetadata:
    """Wraps OperationMetadata, preserving the complete provider output."""

    def __init__(self, inner: OperationMetadataProto) -> None:
        self._inner = inner

    @property
    def proto(self) -> OperationMetadataProto:
        """Return the underlying generated message."""
        return self._inner

    @property
    def key_version(self) -> int:
        """Return the key version the operation was performed under."""
        return self._inner.key_version

    @property
    def api_version(self) -> str:
        """Return the API version the operation was performed under."""
        return self._inner.api_version

    @property
    def user_context(self) -> dict[str, str]:
        """Return the user-supplied context key-value pairs."""
        return dict(self._inner.user_context)

    def to_dict(self) -> dict[str, object]:
        """Render the metadata preserving proto field and enum names."""
        return MessageToDict(
            self._inner,
            preserving_proto_field_name=True,
            use_integers_for_enums=False,
        )


def metadata_from_proto(inner: OperationMetadataProto | None) -> OperationMetadata | None:
    """Wrap a metadata message, returning None when absent."""
    if inner is None:
        return None
    return OperationMetadata(inner)
