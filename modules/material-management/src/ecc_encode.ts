// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import BN from 'bn.js'
import { NodeECDHCurve, WebCryptoECDHCurve } from './algorithm_suites'
import { needs } from './needs'

const prime256v1 = eccEncodeCompressedPoint(32)
const secp384r1 = eccEncodeCompressedPoint(48)

type encodeNamedCurves = {
  [K in NodeECDHCurve | WebCryptoECDHCurve]: (
    publicKey: Uint8Array
  ) => Uint8Array
}

export const encodeNamedCurves: Readonly<encodeNamedCurves> = Object.freeze({
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
function eccEncodeCompressedPoint(keyLength: number) {
  return function encode(publicKey: Uint8Array) {
    /* Precondition: publicKey must be the right length.
     * The format for the public key is [type, ...keyLength, ...keyLength]
     */
    needs(publicKey.byteLength === 1 + keyLength * 2, 'Malformed public key.')

    // const type = publicKey[0]
    const x = publicKey.slice(1, keyLength + 1)
    const y = publicKey.slice(keyLength + 1, keyLength * 2 + 1)

    const yOrder = new BN([...y]).mod(new BN(2)).toNumber() + 2

    const compressPoint = new Uint8Array(1 + x.length)
    compressPoint.set([yOrder], 0)
    compressPoint.set(x, 1)

    return compressPoint
  }
}
