from __future__ import annotations

from citius_api.messages.metadata_pb2 import OperationMetadata as OperationMetadataProto

from citius_sdk.metadata import OperationMetadata, metadata_from_proto


def test_to_dict_preserves_zero_key_version() -> None:
    metadata = OperationMetadata(OperationMetadataProto(key_version=0, api_version="v1"))
    rendered = metadata.to_dict()
    assert rendered["key_version"] == 0
    assert rendered["api_version"] == "v1"


def test_to_dict_preserves_provider_output_bytes() -> None:
    proto = OperationMetadataProto(key_version=3, api_version="v1")
    proto.provider_output.aead_output.nonce = b"\x00\x01\x02\xff"
    proto.provider_output.aead_output.tag_length_bytes = 16
    rendered = metadata_from_proto(proto).to_dict()
    aead = rendered["provider_output"]["aead_output"]
    assert aead["nonce"]
    assert aead["tag_length_bytes"] == 16


def test_metadata_from_proto_returns_none_when_absent() -> None:
    assert metadata_from_proto(None) is None


def test_accessors_expose_underlying_message() -> None:
    proto = OperationMetadataProto(key_version=7, api_version="v2")
    proto.user_context["operator"] = "ciso"
    metadata = OperationMetadata(proto)
    assert metadata.key_version == 7
    assert metadata.api_version == "v2"
    assert metadata.user_context == {"operator": "ciso"}
    assert metadata.proto is proto
