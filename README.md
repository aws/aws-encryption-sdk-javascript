## AWS Encryption SDK for Javascript

The AWS Encryption SDK for Javascript provides a fully compliant,
native Javascript implementation of the [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html)

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

See [Support Policy](./SUPPORT_POLICY.rst) for for details on the current support status of all major versions of this library.

## Client Packages

| Package | Description |
|:--------|:------------|
| [@aws-crypto/client-browser](https://npmjs.com/package/@aws-crypto/client-browser) | Client SDK for **Web applications** |
| [@aws-crypto/client-node](https://npmjs.com/package/@aws-crypto/client-node) | Client SDK for Node.js client applications |

These client packages have everything you need to encrypt/decrypt.
They are the primary starting point.
The AWS Encryption SDK for Javascript is built from a group of modularized packages.
You can also compose the functional packages you need.

### Functional Packages

| Package | Description |
|:--------|:------------|
| [@aws-crypto/encrypt-browser](https://npmjs.com/package/@aws-crypto/encrypt-browser) | Encrypt function for **Web applications** |
| [@aws-crypto/encrypt-node](https://npmjs.com/package/@aws-crypto/encrypt-node) | Encrypt function for Node.js client applications |
| [@aws-crypto/decrypt-browser](https://npmjs.com/package/@aws-crypto/decrypt-browser) | Decrypt function for **Web applications** |
| [@aws-crypto/decrypt-node](https://npmjs.com/package/@aws-crypto/decrypt-node) | Decrypt function for Node.js client applications |
| [@aws-crypto/kms-keyring-browser](https://npmjs.com/package/@aws-crypto/kms-keyring-browser) | Kms keyring for **Web applications** |
| [@aws-crypto/kms-keyring-node](https://npmjs.com/package/@aws-crypto/kms-keyring-node) | Kms keyring for Node.js client applications |
| [@aws-crypto/raw-rsa-keyring-browser](https://npmjs.com/package/@aws-crypto/raw-rsa-keyring-browser) | Raw RSA keyring for **Web applications** |
| [@aws-crypto/raw-rsa-keyring-node](https://npmjs.com/package/@aws-crypto/raw-rsa-keyring-node) | Raw RSA keyring for Node.js client applications |
| [@aws-crypto/raw-aes-keyring-browser](https://npmjs.com/package/@aws-crypto/raw-aes-keyring-browser) | Raw AES keyring for **Web applications** |
| [@aws-crypto/raw-aes-keyring-node](https://npmjs.com/package/@aws-crypto/raw-aes-keyring-node) | Raw AES keyring for Node.js client applications |
| [@aws-crypto/caching-materials-manager-browser](https://npmjs.com/package/@aws-crypto/caching-materials-manager-browser) | Caching Materials Manager for **Web applications** |
| [@aws-crypto/caching-materials-manager-node](https://npmjs.com/package/@aws-crypto/caching-materials-manager-node) | Caching Materials Manager for Node.js client applications |

## Concepts

There are four main concepts that you need to understand to use this library:

### Cryptographic Materials Managers

Cryptographic materials managers (CMMs) are resources that collect cryptographic materials
and prepare them for use by the Encryption SDK core logic.

An example of a CMM is the default CMM,
which is automatically generated anywhere a caller provides a keyring.
The default CMM collects encrypted data keys from it's keyrings.

An example of a more advanced CMM is the caching CMM,
which caches cryptographic materials provided by another CMM.

### Keyrings

Keyrings use wrapping keys to to generate, encrypt, and decrypt data keys.
The keyring that you use determines the source of the unique data keys that protect each message,
and the wrapping keys that encrypt that data key.
An example of a keyring is the `KmsKeyringNode`.

An example of a more advanced keyring is the multi keyring.
A multi keyring can be used to compose keyrings together.

### Wrapping Keys

Wrapping keys are used to protect data keys.
An example of a wrapping key is a `KMS customer master key (CMK)`.

### Data Keys

Data keys are the encryption keys that are used to encrypt your data.
If your algorithm suite uses a key derivation function,
the data key is used to generate the key that directly encrypts the data.

## test

```sh
npm test
```

## License

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.

# Breaking changes from `preview` to `1.0.0`

The AWS Encryption SDK for JavaScript is generally available
as of October 1, 2019.
There were breaking changes during the `preview`.

* Passing encryption context to `encrypt` is now `{ encryptionContext?: EncryptionContext }` [#148][encryptionContext]
* The return value of `encrypt` is now `{result: Uint8Array, messageHeader: MessageHeader}` [#211][encryptResult]
* `encrypt` strictly enforces `plaintextLength` [#213][plaintextLength]

[encryptionContext]: https://github.com/aws/aws-encryption-sdk-javascript/pull/148
[encryptResult]: https://github.com/aws/aws-encryption-sdk-javascript/pull/211
[plaintextLength]: https://github.com/aws/aws-encryption-sdk-javascript/pull/213
