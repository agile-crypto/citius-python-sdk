import pytest

from citius_sdk import ClientConfig, TLSConfig


def test_client_config_builds_message_and_server_name_options() -> None:
    config = ClientConfig(
        endpoint="citius.example:443",
        tls=TLSConfig(server_name="citius.internal"),
        max_send_message_length=1024,
        max_receive_message_length=2048,
    )

    assert config.channel_options == (
        ("grpc.max_send_message_length", 1024),
        ("grpc.max_receive_message_length", 2048),
        ("grpc.ssl_target_name_override", "citius.internal"),
    )


@pytest.mark.parametrize("timeout", [0, -1])
def test_client_config_rejects_non_positive_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        ClientConfig(endpoint="localhost:50051", timeout=timeout)


def test_tls_config_rejects_partial_client_credentials() -> None:
    with pytest.raises(ValueError, match="configured together"):
        TLSConfig(client_cert="client.pem")


def test_tls_config_rejects_options_when_disabled() -> None:
    with pytest.raises(ValueError, match="TLS options"):
        TLSConfig(enabled=False, server_name="localhost")
