# ESDK TestServer — Node.js Language_Server

A hand-implemented [rpcv2Cbor](https://smithy.io/2.0/additional-specs/protocols/smithy-rpc-v2.html)
HTTP server that implements the ESDK TestServer Smithy contract and delegates
each operation to the AWS Encryption SDK for JavaScript built from this
repository's modules.

## Embedded reference to the commons TestServer

The single source of truth for the wire contract — the Smithy model, the one
generated Test_Client, and the one Tests suite — lives in the commons repo:

- Repository: [`aws/aws-crypto-tools-commons`](https://github.com/aws/aws-crypto-tools-commons)
- Model: `esdk/test-server/model/esdk-test-server.smithy`
- Tests: `esdk/test-server/tests`

This repo hosts only the Node.js Language_Server; it consumes the commons
contract. The commons Configuration_Set carries a `javascript` entry pointing
back at this repo, closing the loop described in the TestServer factoring
design.

## What it speaks

- `POST /service/ESDKTestServer/operation/{Operation}`
- Header `smithy-protocol: rpc-v2-cbor`, `Content-Type: application/cbor`
- CBOR map request/response bodies; errors as a CBOR map `{__type, message}`
- Operations: `CreateClient`, `Encrypt`, `Decrypt`, `EncryptStream`,
  `DecryptStream`. The stream variants drive the library's streaming
  `encryptStream`/`decryptStream` APIs (this server is streaming-capable).

## Layout

- `src/cbor.ts` — self-contained CBOR codec (no new dependencies)
- `src/model.ts` — wire shapes + modeled-enum ↔ library-identifier mappings
- `src/bridge.ts` — modeled config → real keyrings/CMMs, operation delegation
- `src/server.ts` — HTTP wire layer, routing, error mapping
- `src/main.ts` — entry point (port from argv, `ESDK_TESTSERVER_PORT`, or 8095)

The server consumes the repo's own built modules (`@aws-crypto/client-node`)
through the root workspace install; it declares no dependencies of its own and
changes nothing about the published packages. Node.js >= 16 is required.

## Running

```bash
make run-server PORT=8095        # foreground (builds modules first)
# or, orchestrated:
make start-server PORT=8095
make wait-for-server PORT=8095
make stop-server PORT=8095
make test                        # unit/protocol tests, no AWS credentials
```

## Running the full cross-language matrix

```bash
make test-server                 # clones commons and delegates to its orchestrator
```

Needs AWS credentials and a JDK 21+ (`JAVA_HOME`).
