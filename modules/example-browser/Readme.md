# AWS Encryption SDK for Javascript examples in a browser

The AWS Encryption SDK for JavaScript is a client-side encryption library designed to make it easy for everyone to encrypt and decrypt data using industry standards and best practices. It uses a data format compatible with the AWS Encryption SDKs in other languages. For more information on the AWS Encryption SDKs in all languages, see the [Developer Guide](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html).

## About example-browser
This repository holds examples for encrypting and decrypting in a browser using KMS and RSA keys.

This package is intended to act as a working example. It is not intended for direct use by clients. To get started with the AWS Encryption SDK for JavaScript, follow the instructions in [the README](https://github.com/awslabs/aws-encryption-sdk-javascript/blob/master/README.md).

# KMS Simple Example

This is a simple example of using a KMS Keyring to encrypt and decrypt using the AWS Encryption SDK for Javascript in a browser. See kms_simple.ts for more information.

# RSA Simple Example

This is a simple example of using a raw RSA Keyring to encrypt and decrypt using the AWS Encryption SDK for Javascript in a browser. See rsa_simple.ts for more information.

# AES Simple Example

This is a simple example of using a raw AES Keyring to encrypt and decrypt using the AWS Encryption SDK for Javascript in a browser. See aes_simple.ts for more information.

# Multi Keyring Example

This is a simple example of combining an KMS Keyring and a raw AES Keyring to encrypt and decrypt using the AWS Encryption SDK for Javascript in a browser. See multi_keyring.ts for more information.

# To test KMS encryption in a browser locally on OSX

```
npm run example-kms
open html/kms_simple.html
```

# To test RSA encryption in a browser locally on OSX

```
npm run example-rsa
open html/rsa_simple.html
```

# To test AES encryption in a browser locally on OSX

```
npm run example-aes
open html/aes_simple.html
```

# To test Multi Keyring encryption in a browser locally on OSX

```
npm run example-multi-keyring
open html/multi_keyring_simple.html
```

## License

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.
