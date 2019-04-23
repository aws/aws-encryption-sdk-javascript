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

/* WebCrypto expects the ECDSA signature to be "raw" formated.
 * e.g. concat(r,s) where r and s are padded to key length bytes.
 * The AWS Encryption SDK expects the signature to be DER encoded.
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#footer-structure
 */

// @ts-ignore
import asn from 'asn1.js'
import { concatBuffers } from './concat_buffers'
import {
  needs,
  WebCryptoAlgorithmSuite, // eslint-disable-line no-unused-vars
  WebCryptoECDHCurve // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'

// https://tools.ietf.org/html/rfc3279#section-2.2.2
const ECDSASignature = asn.define('ECDSASignature', function (this: any) {
  this.seq().obj(
    this.key('r').int(),
    this.key('s').int()
  )
})

// Map the ECDSA Curve to key lengths
const keyLengthBytes : {[key in WebCryptoECDHCurve]: number} = Object.freeze({
  'P-256': 32,
  'P-384': 48
})

/**
 * WebCrypto subtle.verify expect the signature to be "raw" formated e.g. concat(r,s)
 * where r and s are padded to the key length in bytes.
 *
 * @param derSignature [Uint8Array] The DER formated signature from an Encryption SDK formated blob
 * @param suite [WebCryptoAlgorithmSuite] The Algorithm suite used to create the signature
 * @returns Uint8Array The raw formated signature (r,s) used to verify in WebCrypto
 */
export function der2raw (derSignature: Uint8Array, { signatureCurve }: WebCryptoAlgorithmSuite): Uint8Array {
  /* Precondition: Do not attempt to RAW format if the suite does not support signing. */
  if (!signatureCurve) throw new Error('AlgorithmSuite does not support signing')

  const _keyLengthBytes = keyLengthBytes[signatureCurve]

  // A little more portable than Buffer.from, but not much
  const { r, s } = ECDSASignature.decode(new asn.bignum.BN(derSignature).toArrayLike(Buffer), 'der')

  const rLength = r.byteLength()
  const sLength = r.byteLength()

  return concatBuffers(
    new Uint8Array(_keyLengthBytes - rLength),
    r.toArrayLike(Uint8Array),
    new Uint8Array(_keyLengthBytes - sLength),
    s.toArrayLike(Uint8Array)
  )
}

/**
 * WebCrypto subtle.sign returns the signature "raw" formated e.g. concat(r,s)
 * where r and s are padded to the key length in bytes.
 * The Encryption SDK expects the signature to be DER encoded.
 *
 * @param rawSignature [Uint8Array] The "raw" formated signature from WebCrypto subtle.sign
 * @param suite [WebCryptoAlgorithmSuite] The Algorithm suite used to create the signature
 * @returns Uint8Array The DER formated signature
 */
export function raw2der (rawSignature: Uint8Array, { signatureCurve }: WebCryptoAlgorithmSuite): Uint8Array {
  /* Precondition: Do not attempt to DER format if the suite does not support signing. */
  if (!signatureCurve) throw new Error('AlgorithmSuite does not support signing')

  const { byteLength } = rawSignature

  const _keyLengthBytes = keyLengthBytes[signatureCurve]

  /* Precondition: The total raw signature length is twice the key length bytes. */
  needs(byteLength === 2 * _keyLengthBytes, 'Malformed signature.')

  // A little more portable than Buffer.from, but not much
  const r = new asn.bignum.BN(rawSignature.slice(0, _keyLengthBytes)).toArrayLike(Buffer)
  const s = new asn.bignum.BN(rawSignature.slice(_keyLengthBytes)).toArrayLike(Buffer)

  return ECDSASignature.encode({ r, s }, 'der')
}
