/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import BN from 'bn.js' // eslint-disable-line no-unused-vars
import { ec as EC } from 'elliptic'
import {
  createHash,
  Hash // eslint-disable-line no-unused-vars
} from 'crypto'
import { randomRangeBNjs } from './random_range'
import { Rfc5915Key } from './pem_decode'

const SHA256_ECDSA_P256 = Object.freeze(<ECDSAInput>{
  curve: 'p256',
  hash: 'sha256',
  length: 71
})

const SHA384_ECDSA_P384 = Object.freeze(<ECDSAInput>{
  curve: 'p384',
  hash: 'sha384',
  length: 103
})

export type NodeECDSACurve = 'prime256v1'|'secp384r1'

export const supported:{[key in NodeECDSACurve]: () => SignComponents} = Object.freeze({
  'prime256v1': () => ecdsaSignComponents(SHA256_ECDSA_P256),
  'secp384r1': () => ecdsaSignComponents(SHA384_ECDSA_P384)
})

type ECDSAInput = Readonly<{
  curve: 'p256'|'p384',
  hash: 'sha256'|'sha384',
  length: 71|103
}>

function ecdsaSignComponents ({ curve, hash, length }: ECDSAInput): SignComponents {
  const ec = new EC(curve)
  const _hash = createHash(hash)
  const n = <BN>ec.n
  /* randomRange does returns a value from 0 - bound
   * but I need:
   * Select a cryptographically secure random integer k from [1,n-1].
   * See:https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf
   * Specifically Appendix
   * B.5.2 Per-Message Secret Number Generation by Testing Candidates
   * So use use n - 1 and then add 1 back on.
   */
  const nMinus1 = n.subn(1)
  const k = () => randomRangeBNjs(nMinus1).addn(1)

  return { _hash, sign }

  /**
   * This signature is *not* constant time.  I believe that this is OK at this time
   * because the signature is _only_ used to sign with an ephemeral key.
   * @param pem pem formated string
   */
  function sign (pem: string): Buffer {
    const { parameters, privateKey } = Rfc5915Key.decode(pem, 'pem', { label: 'EC PRIVATE KEY' })
    if (parameters !== curve) throw new Error(`Curve ${parameters} in pem does not match ${curve}`)

    const msg = _hash.digest()
    let sig: EC.Signature
    let signature: number[] = []

    while (signature.length !== length) {
      // @ts-ignore The current types require `pers` and think `k` is a value, not a function.
      sig = ec.sign(msg, privateKey, 'binary', { k })
      signature = sig.toDER()

      /* Most of the time, a signature of the wrong length can be fixed
       * by negating s in the signature relative to the group order (n).
       */
      if (signature.length !== length) {
        signature = sig.toDER.call({
          r: sig.r,
          s: n.sub(sig.s),
          recoveryParam: sig.recoveryParam
        })
      }
    }
    const { buffer, byteOffset, byteLength } = new Uint8Array(signature)
    return Buffer.from(buffer, byteOffset, byteLength)
  }
}

interface SignComponents {
  _hash: Hash,
  sign: (pem: string) => Buffer
}
