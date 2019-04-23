# AWS Encryption SDK for Javascript Web Crypto examples

This repository holds examples for encrypt and decrypt in a browser
using KMS and RSA keys.

# To test KMS encryption in a browser locally on OSX

```
npm run example:kms
open kms_simple.html
```

# To test RSA encryption in a browser locally on OSX

```
npm run example:rsa
open rsa_simple.html
```

# To Build the Python Encryption SDK test compatibility

```
cd packages/web-crypto-sdk-example/python_test
pip3 install aws_encryption_sdk cryptography -t .
```

# To get a cipherBlob from the browser and test it in Python

1. Open an example html
1. copy blob in browser
1. Open `packages/web-crypto-sdk-example/python_test/sdk_python_test.py`
1. paste blob from browser into the string `fromBrowser`
1. `python3 packages/web-crypto-sdk-example/python_test/sdk_python_test.py`
