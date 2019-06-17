# AWS Encryption SDK for Javascript Node.js examples

This repository includes examples for encrypting and decrypting in Node.js. These are not for production use.

>To run this example, the reader must have an AWS account with at least one customer managed CMK. To encrypt CMK must have kms:GenerateDataKey permission. To decrypt, the CMK must have kms:Decrypt permission. The CMKs in these examples *are only* for example. *Replace these CMK's with your own*.

## KMS Simple

This is an example of using KMS to encrypt and decrypt a simple string. See kms_simple.ts for a more detailed explanation.

## KMS Stream

This is an example of using KMS to encrypt and decrypt a file stream. See kms_stream.ts for a more detailed explanation.

## KMS Regional Discovery

This is an example of using a KMS Regional Discovery Keyring that limits the AWS Encryption SDK to CMKs in a particular AWS Region(s), as opposed to a KMS Discovery Keyring that doesn't specify any CMKs and will therefore use CMKs from any region available. See kms_regional_discovery.ts for a more detailed explanation.

## RSA Simple

This is an example of using RSA to encrypt and decrypt a simple string. This has some advantages for certain use cases, but we recommend that you use a keyring that protects your wrapping keys and performs cryptographic operations within a secure boundary, such as the KMS keyring, which uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS unencrypted, rather than RSA. See rsa_simple.ts for a more detailed explanation.

## How to Use

Run `npm test` to see these examples in action.

## License

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.
