# AWS Encryption SDK for Javascript Browser Integration

This repository is for compatibility tests with the other versions of the AWS Encryption SDK.
It's designed to facilitate testing for the set of test vectors of the AWS Encryption SDK. 
The test vectors can be found [here] (https://github.com/awslabs/aws-encryption-sdk-test-vectors/tree/a28851a188163e45b8cbf94c1d5a1e67e9622aa8).

This package will not add any dependencies in your environment, but it can be used to test the environment.   

# To test browser compatibility
1. Get a manifest zip file from aws-encryption-sdk-test-vectors or a supported format.
1. Use `npm run build_fixtures -- -v path/to/zip` to extract the fixtures from the zip file.
1. Run `npm run karma` to  execute the extracted tests.
