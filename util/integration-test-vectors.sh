# Single source of truth for integration test vector locations.
# Sourced by the integration-* and verdaccio-* npm scripts.
export LOCAL_TEST_VECTORS="aws-encryption-sdk-test-vectors/vectors/awses-decrypt/python-2.3.0.zip"
export ENCRYPT_MANIFEST_LIST="https://raw.githubusercontent.com/awslabs/aws-crypto-tools-test-vector-framework/master/features/CANONICAL-GENERATED-MANIFESTS/0003-awses-message-encryption.v1.json"
export ENCRYPT_KEY_MANIFEST="https://raw.githubusercontent.com/awslabs/aws-crypto-tools-test-vector-framework/master/features/CANONICAL-GENERATED-MANIFESTS/0002-keys.v1.json"
export DECRYPT_ORACLE="https://xi1mwx3ttb.execute-api.us-west-2.amazonaws.com/api/v0/decrypt"
