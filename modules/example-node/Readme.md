# AWS Encryption SDK for Javascript Node.js examples

This repository includes examples for encrypting and decrypting in Node.js. These are not for production use.

To run this example, you must have an AWS account with at least one AWS Key Management Service (AWS KMS) customer managed CMK.
To encrypt, CMK must have kms:GenerateDataKey permission. 
To decrypt, the CMK must have kms:Decrypt permission.
The CMKs in these examples are only for *example*. *Replace these CMK's with your own*.

## KMS Simple

This is an example of using the AWS Encryption SDK to encrypt and decrypt a simple string. 
For a more detailed explanation, see kms_simple.ts.

## KMS Stream

This is an example of using a KMS keyring to encrypt and decrypt a file stream. 
For a more detailed explanation, see kms_stream.ts.

## KMS Regional Discovery

This is an example of using a KMS Regional Discovery Keyring that limits the AWS Encryption SDK to CMKs in a particular AWS Region(s).
This is different from a KMS Discovery Keyring that doesn't specify any CMKs and will therefore use CMKs from any region available. 
For a more detailed explanation, see kms_regional_discovery.ts.

## RSA Simple

This is an example of using a RSA key pair to encrypt and decrypt a simple string. 
This has some advantages for certain use cases, but we recommend that you use a keyring that protects your wrapping keys and performs cryptographic operations within a secure boundary. This is how a KMS keyring works: it uses AWS Key Management Service (AWS KMS) customer master keys (CMKs) that never leave AWS KMS unencrypted. 
For a more detailed explanation, see rsa_simple.ts.

## How to Use

To see these examples in action, run `npm test`.

## License

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.
