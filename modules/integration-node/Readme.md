# AWS Encryption SDK for Javascript Node.js Integration

This repository is for compatibility tests with the other versions of the AWS Encryption SDKs.
It's purpose is to facilitate testing the set of test vectors the AWS Encryption SDK.
The test vectors can be found at https://github.com/awslabs/aws-encryption-sdk-test-vectors.
Manifest information can be found at https://github.com/awslabs/aws-crypto-tools-test-vector-framework.

It does not provide any useful functionality upon which you may want to build any dependencies.
Instead you want to use it to verify environments (make sure the AWS Encryption SDK works on them).

# To test Node.js compatibility

1. Download a manifest zip file from aws-encryption-sdk-test-vectors or a supported format.
1. Select or download both an encrypt manifest list and key manifest from aws-crypto-tools-test-vector-framework.
1. Execute the CLI to run the integration tests for decrypt and encrypt.

## integration-node is installed as a dependency or globally

### decrypt tests
`integration_node decrypt -v path/to/test/vectors/zip`

### encrypt tests
`integration_node encrypt -m "path/or/url/to/manifest" -k "path/or/url/to/key" -o "url/to/decrypt/oracle"`

## integration-node has been checked out local

### decrypt tests
`npm run integration_node -- decrypt -v path/to/test/vectors/zip`

### encrypt tests
`npm run integration_node -- encrypt -m "path/or/url/to/manifest" -k "path/or/url/to/key" -o "url/to/decrypt/oracle"`

## Test Integration
Just run

```sh
npm test
```

to run the tests.
