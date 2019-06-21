# AWS Encryption SDK for Javascript Node.js examples

The AWS Encryption SDK for JavaScript is a client-side encryption library
designed to make it easy for everyone to encrypt
and decrypt data using industry standards and best practices.
It uses a data format compatible with the AWS Encryption SDKs in other languages.
For more information on the AWS Encryption SDKs in all languages,
see the [Developer Guide](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html).

The CMKs in these examples are only for *example*.
*Replace these CMKs with your own*.

## About example-node
This repository includes examples for encrypting and decrypting in Node.js.
**These are not for production use.**

## KMS Simple

This is a simple example of using a KMS keyring to encrypt
and decrypt using the AWS Encryption SDK for Javascript in Node.js.
For more information, see kms_simple.ts.

## KMS Stream

This is an example of using a KMS keyring to encrypt and decrypt a file stream. 
For a more detailed explanation, see kms_stream.ts.

## KMS Regional Discovery

This is an example of using a KMS Regional Discovery Keyring
that limits the AWS Encryption SDK to CMKs in a particular AWS Region(s).
This is different from a KMS Discovery Keyring that doesn't specify any CMKs
and will therefore use CMKs from any region available. 
For a more detailed explanation, see kms_regional_discovery.ts.

## RSA Simple

This is an example of using a RSA key pair to encrypt and decrypt a simple string. 
This has some advantages for certain use cases,
but we recommend that you use a keyring that protects your wrapping keys
and performs cryptographic operations within a secure boundary.
The KMS keyring uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS unencrypted. 
For a more detailed explanation, see rsa_simple.ts.

## AES Simple

This is an example of using a shared secret to encrypt and decrypt a simple string. 
This has some advantages for certain use cases,
but we recommend that you use a keyring that protects your wrapping keys
and performs cryptographic operations within a secure boundary.
The KMS keyring uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS unencrypted. 
For a more detailed explanation, see aes_simple.ts.

## Multi Keyring

This is a simple example of combining an KMS keyring
and a raw AES keyring to encrypt
and decrypt using the AWS Encryption SDK for Javascript in Node.js
This has some advantages for certain use cases,
but we recommend that you use a keyring that protects your wrapping keys
and performs cryptographic operations within a secure boundary.
The KMS keyring uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS unencrypted. 
For a more detailed explanation, see multi_keyring.ts.

## How to Use

To see these examples in action, run `npm test`.

## License

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.
