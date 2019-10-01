# AWS Encryption SDK for Javascript examples in a browser

The AWS Encryption SDK for JavaScript is a client-side encryption library
designed to make it easy for everyone to encrypt
and decrypt data using industry standards and best practices.
It uses a data format compatible with the AWS Encryption SDKs in other languages.
For more information on the AWS Encryption SDKs in all languages,
see the [Developer Guide](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html).

The CMKs in these examples are only for *example*.
*Replace these CMKs with your own*.

## About example-browser
This repository holds examples for encrypting and decrypting in a browser.
**These are not for production use.**

This package is intended to act as a working example.
It is not intended for direct use by clients.
To get started with the AWS Encryption SDK for JavaScript,
follow the instructions in [the README](https://github.com/aws/aws-encryption-sdk-javascript/blob/master/README.md).

# KMS Simple Example

This is a simple example of using a KMS keyring to encrypt
and decrypt using the AWS Encryption SDK for Javascript in a browser.
For more information, see kms_simple.ts.

# RSA Simple Example

This is an example of using a RSA key pair to encrypt and decrypt a simple string. 
This has some advantages for certain use cases,
but we recommend that you use a keyring that protects your wrapping keys
and performs cryptographic operations within a secure boundary.
The KMS keyring uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS unencrypted. 
For a more detailed explanation, see rsa_simple.ts.

# AES Simple Example

This is an example of using a shared secret to encrypt and decrypt a simple string. 
This has some advantages for certain use cases,
but we recommend that you use a keyring that protects your wrapping keys
and performs cryptographic operations within a secure boundary.
The KMS keyring uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS unencrypted. 
For a more detailed explanation, see aes_simple.ts.

# Multi keyring Example

This is a simple example of combining an KMS keyring
and a raw AES keyring to encrypt
and decrypt using the AWS Encryption SDK for Javascript in a browser.
This has some advantages for certain use cases,
but we recommend that you use a keyring that protects your wrapping keys
and performs cryptographic operations within a secure boundary.
The KMS keyring uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS unencrypted. 
For a more detailed explanation, see multi_keyring.ts.

# To test KMS encryption in a browser locally on macOS

```
npm run example-kms
open html/kms_simple.html
```

# To test RSA encryption in a browser locally on macOS

```
npm run example-rsa
open html/rsa_simple.html
```

# To test AES encryption in a browser locally on macOS

```
npm run example-aes
open html/aes_simple.html
```

# To test multi-keyring encryption in a browser locally on macOS

```
npm run example-multi-keyring
open html/multi_keyring.html
```

## License

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.
