# AWS Encryption SDK for Javascript Node.js examples

This repository holds examples for encrypt and decrypt in Node.js.
These examples are intended to work in such a way that you can experiment with functional code.  These are not for production use.

> The CMK's in these examples *are only* for example.  They *are public*.  *Replace these CMK's with your own*.

## KMS Simple

This is an example of using KMS to encrypt and decrypt a simple string.  See `kms_simple.ts` for a more detailed explanation.

## KMS Stream

This is an example of using KMS to encrypt and decrypt a file stream. See `kms_stream.ts` for a more detailed explanation.

## KMS Regional Discovery

KMS Keyrings can be put in `discovery` mode, which means that, on decrypt, it will attempt to connect to any region represented in the KMS Keyring by using the `clientProvider`.  However, perhaps for performance, you may want to limit attempts to a set of "close" regions, or, for policy reasons, you want to exclude some regions, which can be done with the `limitRegions` and `excludeRegions` functions, respectively. See `kms_regional_discovery.ts` for a more detailed explanation.

## RSA Simple

This is an example of using RSA to encrypt and decrypt a simple string.  This has some advantages for certain use-cases, but the key management costs are higher than using KMS, which means KMS is generally the best option. See `rsa_simple.ts` for a more detailed explanation.

## How to Use

Run `npm test` to see these examples in action.

## License

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.
