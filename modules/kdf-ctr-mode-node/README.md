# @aws-crypto/kdf-ctr-mode-node

This module exports a Key Derivation Function in Counter Mode with a Pseudo
Random function with HMAC SHA 256 for Node.js.

This module is used in the the AWS Encryption SDK for JavaScript
to provide key derivation for specific algorithm suites.

Specification: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf

## install

```sh
npm install @aws-crypto/kdf-ctr-mode-node
```

## use

```javascript

const digestAlgorithm = 'sha256'
const initialKeyMaterial = gottenFromSomewhereSecure()
const nonce = freshRandomData()
const purpose = Buffer.from('What this derived key is for.', 'utf-8')
const expectedLength = 32

const KDF = require('@aws-crypto/kdf-ctr-mode-node')
const derivedKey = KDF.kdfCounterMode({
        digestAlgorithm,
        ikm: initialKeyMaterial,
        nonce,
        purpose,
        expectedLength,
      })
```

## test

```sh
npm test
```

## license

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.
