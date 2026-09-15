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
