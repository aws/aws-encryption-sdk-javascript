# @aws-crypto/hkdf-node

Another HMAC-based Key Derivation Function for node.js.
The function is very simple,
but having a controlled, reviewed, and blessed version is valuable.
As a crypto primitive this is helpful to have,
but the nodejs `crypto` module only exposes what openssl supports.
Since it is so simple and derivable,
there are no plans to include this in core.

spec: https://tools.ietf.org/html/rfc5869

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
