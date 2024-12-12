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
const HKDF = require('@aws-crypto/hkdf-node')
const expand = HKDF('sha256')('some key', 'some salt')
const info = { some: 'info', message_id: 123 }
const key = expand(32, Buffer.from(JSON.stringify(info)))
```

## test

```sh
npm test
```

## license

This SDK is distributed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0),
see LICENSE.txt and NOTICE.txt for more information.
