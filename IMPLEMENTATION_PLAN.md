# Citius Python SDK Implementation Plan

Status: in progress
Created: 2026-09-17
Target repository: `/home/navaneeth/GolandProjects/Citius/citius-python-sdk`
Generated API dependency: `citius-api-python` (installed as `citius_api`)
Reference SDK: `/home/navaneeth/GolandProjects/Citius/citius-go-sdk`
Primary consumer: `/home/navaneeth/GolandProjects/Citius/citius-ui`

## 1. Objective

Provide an ergonomic, async-first Python client SDK for the Citius gRPC services
that mirrors the boundaries already proven in `citius-go-sdk`, while remaining
idiomatic Python. The SDK owns connection configuration, TLS/mTLS, per-RPC
bearer metadata, deadlines, message-size limits, normalized errors, and
information-preserving response models. It does **not** own the generated
protobuf/gRPC bindings (those live in `citius-api-python`), interactive login,
cookie sessions, or Zitadel administration.

This directly satisfies **Phase 1** of the Citius UI plan and unblocks UI RPC
wiring: *"Full RPC wiring starts after the Python SDK can make one authenticated
unary call."*

## 2. Design principles carried from `citius-go-sdk`

The Go SDK establishes a per-service package with a consistent five-file shape.
Adapt the responsibilities — not the file names — to Python:

| Go SDK concept | Python SDK equivalent |
|---|---|
| `client/<svc>/client.go` — public methods, timeout wrapping | `services/<svc>.py` — `Client` class with async methods |
| `client/<svc>/rpc_client.go` — `RPCClient` interface + adapter | Generated `*Stub` used directly (no adapter needed) |
| `client/<svc>/requests.go` — fluent builders that accumulate errors, then `.build()` | Request builders / typed helpers that validate then return a proto message |
| `client/<svc>/responses.go` — wrap inner proto, expose accessors + `Metadata()` | Response wrappers exposing accessors and `metadata` |
| `client/config/config.go` — resolved service config, TLS, auth | `config.py` (`ClientConfig`, `TLSConfig`) — already present |
| `client/auth/{token,interceptor}.go` | `auth.py` (`TokenProvider`, `BearerAuthInterceptor`) — already present |
| `client/internal/errors/errors.go` — structured `Error` + `Code` | `errors.py` — `CitiusError` hierarchy mapping gRPC status codes |
| `client/internal/dial/dial.go` — channel + credential construction | `channel.py` (`create_channel`) — already present |
| `client/crypto/metadata.go` — `OperationMetadata` wrapper, no info loss | `metadata.py` — `OperationMetadata` helpers |

Key stylistic rules retained from the Go SDK:

- Request construction validates structurally and reports **all** problems, not
  just the first, before any network call.
- Response wrappers preserve the complete inner proto; long-lived crypto outputs
  (signature/ciphertext) always carry their full `OperationMetadata`
  (`key_version`, `provider_output`, `api_version`). Copying only the bytes is
  never a valid compatibility workflow.
- The bearer token is supplied **per call** via an interceptor, never fixed
  globally on a shared multi-user channel.
- Every service client supports an explicit insecure local-development mode and
  TLS/mTLS for real deployments.
- Errors are normalized so callers can distinguish `UNAUTHENTICATED`,
  `PERMISSION_DENIED`, `UNIMPLEMENTED`, `NOT_FOUND`, `FAILED_PRECONDITION`,
  invalid-argument, and connectivity/deadline failures.

## 3. Current state (verified 2026-09-17)

Already implemented:

- `src/citius_sdk/config.py` — `TLSConfig`, `ClientConfig` (endpoint, timeout,
  message-size limits, channel options, server-name override).
- `src/citius_sdk/auth.py` — `TokenProvider` protocol, `StaticTokenProvider`,
  `BearerAuthInterceptor` (unary-unary only).
- `src/citius_sdk/channel.py` — `create_channel` for insecure and TLS/mTLS.
- `src/citius_sdk/services/discovery.py` — `DiscoveryClient` reference pattern
  (`connect`, per-call deadline, `close`, async context manager).
- `tests/test_config.py`, `tests/test_discovery.py` — in-process fake gRPC
  server pattern with a rotating token provider.

Missing (this plan's scope):

- Streaming service clients: `provider`, `key_establishment`, `streaming_crypto`.
- TLS/mTLS handshake coverage and generated-code drift fixtures.
- Contract/integration coverage against a live server distinguishing auth failures.

Completed since 2026-09-17:

- `errors.py` — `CitiusError` hierarchy, `from_rpc_error`, and `map_rpc_errors`.
- `metadata.py` — lossless `OperationMetadata` wrapper with `to_dict()`.
- `version.py` — recorded API pin and `check_api_compatibility()`.
- `auth.py` — unary and streaming bearer interceptors plus `CallableTokenProvider`.
- `services/crypto.py` — `Encrypt`, `Decrypt`, `Sign`, `Verify`, `DigestSign`,
  `DigestVerify` with metadata-preserving responses.
- `services/key_management.py` — `CreateKey`, `ReadKey`, `TransformKey`.
- `services/crypto_policy.py` — `CreateCryptoPolicy`, `ReadCryptoPolicy`,
  `UpdateCryptoPolicy`.
- `tests/` — `test_errors.py`, `test_version.py`, `test_crypto.py`,
  `test_key_management.py`, `test_crypto_policy.py`.

## 4. Generated API surface (from `citius_api`)

Import paths follow `citius_api.services.<svc>_service_pb2[_grpc]`.

| Service | Stub | Implemented server RPCs (initial SDK scope) | Contract-only RPCs (later) |
|---|---|---|---|
| Crypto Policy | `CryptoPolicyServiceStub` | `CreateCryptoPolicy`, `ReadCryptoPolicy`, `UpdateCryptoPolicy` | `DeleteCryptoPolicy`, `ListCryptoPolicies`, `EvaluatePolicy`, `BatchEvaluatePolicy` |
| Key Management | `KeyManagementServiceStub` | `CreateKey`, `ReadKey`, `TransformKey` | `RotateKey`, `ListKeys`, `DeleteKey`, `UpdateKeyPolicy`, `UpdateKeyState`, `MigrateKey`, `ValidateKeyOperation`, `ImportKey`, `ExportKey` |
| Crypto | `CryptoServiceStub` | `Encrypt`, `Decrypt`, `Sign`, `Verify`, `DigestSign`, `DigestVerify` | `GenerateMAC`, `VerifyMAC`, `Digest`, `Xof`, `GenerateRandom`, `SeedRandom` |
| Algorithm Discovery | `AlgorithmDiscoveryServiceStub` | `ListTemplates` (done) | `GetTemplate`, `ListScopes`, others as implemented |
| Provider | `ProviderServiceStub` | none implemented yet | catalog / instance / match RPCs |
| Key Establishment | `KeyEstablishmentServiceStub` | none implemented yet | establishment RPCs |
| Streaming Crypto | `StreamingCryptoServiceStub` | none implemented yet | streaming RPCs |

The SDK exposes contract-only RPCs as callable methods so the UI can surface a
truthful `UNIMPLEMENTED` status; it never simulates server behavior.

## 5. Target repository layout

```text
citius-python-sdk/
├── IMPLEMENTATION_PLAN.md
├── README.md
├── pyproject.toml
├── src/citius_sdk/
│   ├── __init__.py          # public exports
│   ├── config.py            # ClientConfig, TLSConfig            (done)
│   ├── auth.py              # TokenProvider, interceptors        (extend)
│   ├── channel.py           # create_channel                    (done)
│   ├── errors.py            # CitiusError hierarchy + mapping    (new)
│   ├── metadata.py          # OperationMetadata helpers          (new)
│   ├── version.py           # compatible API version + check     (new)
│   └── services/
│       ├── __init__.py
│       ├── discovery.py            (done)
│       ├── crypto.py               (new)
│       ├── key_management.py       (new)
│       ├── crypto_policy.py        (new)
│       ├── provider.py             (later)
│       ├── key_establishment.py    (later)
│       └── streaming_crypto.py     (later)
└── tests/
    ├── test_config.py              (done)
    ├── test_discovery.py           (done)
    ├── test_errors.py              (new)
    ├── test_crypto.py              (new)
    ├── test_key_management.py      (new)
    ├── test_crypto_policy.py       (new)
    ├── test_tls.py                 (new)
    └── test_version.py             (new)
```

## 6. Component design

### 6.1 Error normalization (`errors.py`)

Mirror the Go SDK's structured `Error` + `Code`, but map gRPC status codes to a
Python exception hierarchy so callers can `except` precisely:

```text
CitiusError(Exception)          # base; carries grpc code, message, safe details
├── AuthenticationError         # UNAUTHENTICATED
├── PermissionDeniedError       # PERMISSION_DENIED
├── NotFoundError               # NOT_FOUND
├── InvalidArgumentError        # INVALID_ARGUMENT
├── FailedPreconditionError     # FAILED_PRECONDITION (policy/lifecycle)
├── UnimplementedError          # UNIMPLEMENTED
├── DeadlineExceededError       # DEADLINE_EXCEEDED
└── UnavailableError            # UNAVAILABLE / connectivity / TLS
```

- `from_rpc_error(err: grpc.aio.AioRpcError) -> CitiusError` maps `err.code()`
  to the matching subclass and preserves `code`, `details()`, and safe
  `grpc-status-details-bin` fields where present via `grpcio-status`.
- A `map_rpc_errors` async decorator/wrapper is applied inside each client
  method so raw `AioRpcError` never leaks to callers.
- No token, secret, or key material is ever placed in an error message.

### 6.2 Operation metadata (`metadata.py`)

`OperationMetadata` wraps `citius_api.messages.metadata_pb2.OperationMetadata`
with lossless accessors: `key_version`, `provider_output` (nonce/IV + encoding),
`api_version`, and user context. Provide `to_dict()` preserving field and enum
names (no information loss) for history/rendering by the UI.

### 6.3 Version compatibility (`version.py`)

- Record the compatible `citius-api-python` version/commit the SDK is built and
  tested against (the pin already in `pyproject.toml`, `@9297df0`).
- `check_api_compatibility()` reads the installed `citius_api` version (or a
  recorded generation manifest) and raises a clear error on incompatible drift.
- A test asserts the installed generated package matches the recorded pin so CI
  fails on undeclared drift, matching the Go SDK's generated-code drift check.

### 6.4 Auth interceptors (`auth.py`, extend)

- Keep `BearerAuthInterceptor` (unary-unary).
- Add `StreamUnaryBearerInterceptor`, `UnaryStreamBearerInterceptor`, and
  `StreamStreamBearerInterceptor` so streaming services (later phases) attach the
  same per-call token. Share the metadata-merge helper to avoid duplication.
- Add a `CallableTokenProvider` that wraps an async callable, so the UI can pass
  a session-backed refresher without defining a class.

### 6.5 Service clients (`services/<svc>.py`)

Each client follows the established `DiscoveryClient` shape:

- `__init__(channel, *, timeout, close_channel=False)`.
- `connect(config, *, token_provider=None)` classmethod that owns its channel.
- One async method per RPC returning a response wrapper, applying a per-call
  deadline (`timeout` override allowed) and `map_rpc_errors`.
- `close()`, `__aenter__`, `__aexit__`.

Request ergonomics (adapted from Go `requests.go`): provide small typed
constructor helpers for the important RPCs (e.g. `encrypt_request(key_name,
plaintext, ...)`) that validate and return the proto, while still accepting a
raw generated request for advanced callers. Response wrappers expose accessors
plus `metadata` (see 6.2).

## 7. Implementation phases and commit plan

Small, reviewable commits. Each commit leaves the repo runnable, adds
proportional tests, and updates the README when public behavior changes.

### Phase S0 — foundations: errors, metadata, version, auth (blocking)

1. Add `errors.py` with the exception hierarchy and `from_rpc_error`.
2. Add `metadata.py` with the `OperationMetadata` wrapper and `to_dict()`.
3. Add `version.py` with the recorded API pin and `check_api_compatibility()`.
4. Extend `auth.py` with streaming interceptors and `CallableTokenProvider`.
5. Export new symbols from `__init__.py`.
6. Tests: `test_errors.py` (code mapping, no-leak), `test_version.py` (pin match).

Exit criteria: error mapping and version check are unit-tested; existing
discovery tests still pass.

### Phase S1 — crypto client (initial implemented RPCs)

1. Add `services/crypto.py` with `Encrypt`, `Decrypt`, `Sign`, `Verify`,
   `DigestSign`, `DigestVerify`; response wrappers preserve `OperationMetadata`.
2. Add contract-only stubs (`GenerateMAC`, `VerifyMAC`, `Digest`, `Xof`,
   `GenerateRandom`, `SeedRandom`) that surface `UnimplementedError` truthfully.
3. Tests: `test_crypto.py` with in-process fake server — success, missing token
   → `AuthenticationError`, denied → `PermissionDeniedError`, deadline, and a
   metadata-preservation assertion for a sign/encrypt round-trip.

Exit criteria: a fake-server test performs Sign then Verify using only the
returned wrapper (including `key_version`), proving lossless metadata.

### Phase S2 — key management and crypto policy clients

1. Add `services/key_management.py` (`CreateKey`, `ReadKey`, `TransformKey`
   implemented; remaining RPCs present but truthful about availability).
2. Add `services/crypto_policy.py` (`CreateCryptoPolicy`, `ReadCryptoPolicy`,
   `UpdateCryptoPolicy` implemented; list/evaluate/delete present, truthful).
3. Tests: `test_key_management.py`, `test_crypto_policy.py` mirroring S1
   coverage, including a policy → key artifact hand-off shape check.

Exit criteria: policy create/read/update and key create/read/transform succeed
against a fake server and map errors correctly.

### Phase S3 — TLS/mTLS and drift coverage

1. Add `test_tls.py` using the Go SDK `testdata` PEM approach (or generated
   fixtures) to exercise server TLS and mTLS handshakes on a local channel.
2. Add the generated-code drift test tied to the recorded API pin.
3. Document local TLS setup in the README.

Exit criteria: TLS, mTLS, insecure-dev, missing-token, refreshed-token, timeout,
and error-mapping tests pass; drift check fails on mismatch.

### Phase S4 — later services (as server RPCs land)

Add `provider.py`, `key_establishment.py`, and `streaming_crypto.py` behind the
same patterns once their server handlers are implemented. Streaming reuses the
streaming auth interceptors from S0. These remain callable-but-`UNIMPLEMENTED`
until the server supports them; the SDK never simulates them.

## 8. SDK acceptance gate (from Citius UI plan §13.3)

- [ ] `citius-api-python` pin recorded; CI drift check tied to that commit/tag.
- [ ] SDK pins a compatible generated API version and tests the boundary.
- [ ] Unit tests use in-process fake gRPC servers for every service client.
- [ ] TLS, mTLS, missing-token, refreshed-token, timeout, and error-mapping
      tests pass.
- [ ] A contract test calls one implemented Citius RPC with auth disabled.
- [ ] An integration test calls one implemented RPC with a Zitadel access token
      and distinguishes `UNAUTHENTICATED` from `PERMISSION_DENIED`.
- [ ] Signature/ciphertext response models preserve complete
      `OperationMetadata`, especially `key_version` and provider output.

## 9. Out of scope

- Regenerating or vendoring the API bindings (owned by `citius-api-python`).
- Interactive OIDC login, PKCE, cookies, or server-side sessions (owned by
  `citius-ui`).
- Zitadel administration and permission-catalog definitions (owned by
  `citius-server` / `zitadel-grpc-auth`).
- Cryptographic policy evaluation, template selection, provider matching, or
  authorization decisions (owned by `citius-server`).
