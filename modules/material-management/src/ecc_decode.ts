// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import BN from 'bn.js'
import { NodeECDHCurve, WebCryptoECDHCurve } from './algorithm_suites'
import { needs } from './needs'

const prime256v1 = eccDecodeCompressedPoint(
  new BN(
    'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
    16
  ),
  new BN(
    'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
    16
  ),
  new BN('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B', 16)
  // new BN('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)
)
const secp384r1 = eccDecodeCompressedPoint(
  new BN(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
    16
  ),
  new BN(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
    16
  ),
  new BN(
    'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF',
    16
  )
  // new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973', 16)
)

type decodeNamedCurves = {
  [K in NodeECDHCurve | WebCryptoECDHCurve]: (
    compressedPoint: Uint8Array
  ) => Uint8Array
}
export const decodeNamedCurves: Readonly<decodeNamedCurves> = Object.freeze({
  // NodeJS/OpenSSL names
  prime256v1,
  secp384r1,
  // WebCrypto/Browser names
  'P-256': prime256v1,
  'P-384': secp384r1,
})

/*
 * 1. This only works for prime curves
 * 2. This will not handle the point at infinity
 */
function eccDecodeCompressedPoint(p: BN, a: BN, b: BN /*, order: BN */) {
  const zero = new BN(0)
  const one = new BN(1)
  const two = new BN(2)
  const three = new BN(3)
  const four = new BN(4)

  // # Only works for p % 4 == 3 at this time.
  // # This is the case for all currently supported algorithms.
  // # This will need to be expanded if curves which do not match this are added.
  // #  Python-ecdsa has these algorithms implemented.  Copy or reference?
  // #  https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
  // #  Handbook of Applied Cryptography, algorithms 3.34 - 3.39
  needs(p.mod(four).eq(three), 'Curve not supported at this time')

  const montP = BN.mont(p)
  const redPow = p.add(one).div(four)
  const yOrderMap: { [index: number]: BN } = {
    2: zero,
    3: one,
  }
  const compressedLength = 1 + p.bitLength() / 8
  return function decode(compressedPoint: Uint8Array) {
    /* Precondition: compressedPoint must be the correct length. */
    needs(
      compressedPoint.byteLength === compressedLength,
      'Compressed point length is not correct.'
    )

    const xBuff = compressedPoint.slice(1)
    const keyLength = xBuff.byteLength
    const x = new BN([...xBuff])
    const yOrder = yOrderMap[compressedPoint[0]]
    const x3 = x.pow(three).mod(p)
    const ax = a.mul(x).mod(p)
    const alpha = x3.add(ax).add(b).mod(p)
    const beta = alpha.toRed(montP).redPow(redPow).fromRed()
    if (beta.mod(two).eq(yOrder)) {
      const y = beta
      return returnBuffer(x, y, keyLength)
    } else {
      const y = p.sub(beta)
      return returnBuffer(x, y, keyLength)
    }
  }
}

function returnBuffer(x: BN, y: BN, keyLength: number) {
  return new Uint8Array([
    4,
    ...x.toArray('be', keyLength),
    ...y.toArray('be', keyLength),
  ])
}
