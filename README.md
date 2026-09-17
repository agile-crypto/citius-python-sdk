# citius-python-sdk

Async Python client SDK for the Citius gRPC services. The SDK owns connection
configuration, authentication metadata, deadlines, and ergonomic service
clients. Generated protobuf and gRPC modules remain in `citius-api-python`.

The initial client exposes authenticated template discovery:

```python
from citius_sdk import ClientConfig, StaticTokenProvider, TLSConfig
from citius_sdk.services.discovery import DiscoveryClient

config = ClientConfig(
    endpoint="localhost:50051",
    tls=TLSConfig(enabled=False),
)

async def list_templates():
    async with DiscoveryClient.connect(
        config,
        token_provider=StaticTokenProvider("access-token"),
    ) as discovery:
        return await discovery.list_templates()
```

`TokenProvider.token()` is called for every RPC, allowing a UI session provider
to refresh an access token without rebuilding the channel or service client.

## Available service clients

| Client | Implemented methods |
|---|---|
| `DiscoveryClient` | `list_templates` |
| `CryptoClient` | `encrypt`, `decrypt`, `sign`, `verify`, `digest_sign`, `digest_verify` |
| `KeyManagementClient` | `create_key`, `read_key`, `transform_key` |
| `CryptoPolicyClient` | `create_policy`, `read_policy`, `update_policy` |

Request builders validate structurally and report every problem before any
network call. Signature, ciphertext, and key responses preserve the complete
`OperationMetadata` (including `key_version`) so backward-compatibility
workflows can replay against the original key version.

Failures are normalized to a `CitiusError` hierarchy
(`AuthenticationError`, `PermissionDeniedError`, `NotFoundError`,
`InvalidArgumentError`, `FailedPreconditionError`, `UnimplementedError`,
`DeadlineExceededError`, `UnavailableError`) so callers can distinguish an
authentication failure from a permission denial without inspecting raw gRPC
status codes.

`check_api_compatibility()` verifies the installed `citius-api-python`
distribution matches the version this SDK release was built against.

## Test

```bash
uv run ruff format --check src tests
uv run ruff check src tests
uv run pytest
```
