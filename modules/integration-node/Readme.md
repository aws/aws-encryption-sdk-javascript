# AWS Encryption SDK for Javascript Node.js Integration

This repository is for compatibility tests with the other versions of the AWS Encryption SDKs.
It's purpose is to facilitate testing the set of test vectors the AWS Encryption SDK.
The test vectors can be found at https://github.com/awslabs/aws-encryption-sdk-test-vectors.

It does not provide any useful functionality upon which you may want to build any dependencies.  Instead you want to use it to verify environments (make sure the AWS Encryption SDK works on them).

# To test Node.js compatibility

1. Get a manifest zip file from aws-encryption-sdk-test-vectors or a supported format.
2. Execute the CLI to run the integration tests.

The second step can be done one of two ways

## integration-node is installed as a dependency or globally

`integration_node -v path/to/test/vectors/zip`

## integration-node has been checked out local

`npm run integration_node -- -v path/to/test/vectors/zip`


## Test Integration
Just run

```sh
npm test
```

to run the tests.
