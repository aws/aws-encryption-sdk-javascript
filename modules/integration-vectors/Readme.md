# AWS Encryption SDK for Javascript Test Vectors

This repository is for compatibility tests with the other versions of the AWS Encryption SDKs.
Its purpose is to facilitate testing the set of test vectors the AWS Encryption SDK.
The test vectors can be found at https://github.com/awslabs/aws-encryption-sdk-test-vectors.
Manifest information can be found at https://github.com/awslabs/aws-crypto-tools-test-vector-framework.

It does not provide any useful functionality upon which you may want to build any dependencies.
Instead, you want to use it to verify environments (make sure the AWS Encryption SDK works on them).

# To use, take a dependency on @aws-crypto/integration-vectors

1. Download a manifest zip file from aws-encryption-sdk-test-vectors or a supported format.
1. Select or download both an encryption manifest list and key manifest from aws-crypto-tools-test-vector-framework.
1. Refer to the `integration-node` and/or `integration-browser` for examples of usage.
