/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

import BN from 'bn.js'
import { NodeECDHCurve, WebCryptoECDHCurve } from './algorithm_suites' // eslint-disable-line no-unused-vars
import { needs } from './needs'

const prime256v1 = eccEncodeCompressedPoint(32)
const secp384r1 = eccEncodeCompressedPoint(48)

type encodeNamedCurves = {[K in NodeECDHCurve|WebCryptoECDHCurve]: (publicKey: Uint8Array) => Uint8Array}

export const encodeNamedCurves: Readonly<encodeNamedCurves> = Object.freeze({
  // NodeJS/OpenSSL names
  prime256v1,
  secp384r1,
  // WebCrypto/Browser names
  'P-256': prime256v1,
  'P-384': secp384r1
})

function eccEncodeCompressedPoint (keyLength: number) {
  return function encode (publicKey: Uint8Array) {
    /* Precondition: publicKey must be the right length.
     * The format for the public key is [type, ...keyLength, ...keyLength]
     */
    needs(publicKey.byteLength === 1 + keyLength * 2, 'Malformed public key.')

    // const type = publicKey[0]
    const x = publicKey.slice(1, keyLength + 1)
    const y = publicKey.slice(keyLength + 1, keyLength * 2 + 1)

    const yOrder = (new BN([...y])).mod(new BN(2)).toNumber() + 2

    const compressPoint = new Uint8Array(1 + x.length)
    compressPoint.set([yOrder], 0)
    compressPoint.set(x, 1)

    return compressPoint
  }
}
