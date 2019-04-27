# AWS Encryption SDK for Javascript Browser Integration

This repository is for compatibility tests with the other versions of the AWS Encryption SDK's.
It's purpose is to facilitate testing the set of test vectors the AWS Encryption SDK.
The test vectors can be found at git@github.com:awslabs/aws-encryption-sdk-test-vectors.git

# To test browser compatibility

1. Get a manifest zip file from aws-encryption-sdk-test-vectors or a supported format.
1. Use `npm run build_fixtures -- -v path/to/zip` to extract the fixtures from the zip file
1. Run `npm run karma` execute the extracted tests
