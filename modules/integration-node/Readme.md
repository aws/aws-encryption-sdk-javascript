# AWS Encryption SDK for Javascript Node.js Integration

This repository is for compatibility tests with the other versions of the AWS Encryption SDK's.
It's purpose is to facilitate testing the set of test vectors the AWS Encryption SDK.
The test vectors can be found at https://github.com/awslabs/aws-encryption-sdk-test-vectors

# To test Node.js compatibility

1. Get a manifest zip file from aws-encryption-sdk-test-vectors or a supported format.
1. Execute the cli to run the integration tests

The second step can be done one of two ways

## integration-node is installed as a dependency or globally

`integration_node -v path/to/test/vectors/zip`

## integration-node has been checked out local

`npm run integration_node -- -v path/to/test/vectors/zip`
