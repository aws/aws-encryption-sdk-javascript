# @aws-crypto/hkdf-node

This module exports a HMAC-based Key Derivation Function (HKDF) for Node.js.
HKDF is very simple to implement,
but this module has been reviewed
and has extensive test vectors.

This module is used in the the AWS Encryption SDK for JavaScript
to provide HKDF key derivation for specific algorithm suites.

Specification: https://tools.ietf.org/html/rfc5869

## install

```sh
npm install @aws-crypto/hkdf-node
```

## use

```javascript
  const HKDF = require('@aws-crypto/hkdf-node')
  const expand = HKDF('sha256')('some key', 'some salt')
  const info = {some: 'info', message_id: 123}
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
