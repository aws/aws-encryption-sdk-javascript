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

import { AlgorithmSuite, NodeECDHCurve, WebCryptoECDHCurve } from './algorithm_suites' // eslint-disable-line no-unused-vars
import { encodeNamedCurves } from './ecc_encode'
import { decodeNamedCurves } from './ecc_decode'
import { frozenClass, readOnlyBinaryProperty, readOnlyProperty } from './immutable_class'
import { KeyObject } from 'crypto' // eslint-disable-line no-unused-vars
import { publicKeyPem, privateKeyPem } from './pem_helpers'

/*
 * This public interface to the SignatureKey object is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */

type KeyMaterial = string|Uint8Array|KeyObject|CryptoKey

export class SignatureKey {
  public readonly privateKey!: KeyMaterial
  public readonly compressPoint!: Uint8Array
  public readonly signatureCurve!: NodeECDHCurve|WebCryptoECDHCurve
  constructor (privateKey: KeyMaterial, compressPoint: Uint8Array, suite: AlgorithmSuite) {
    const { signatureCurve: namedCurve } = suite
    /* Precondition: Do not encode a compress point for an algorithm suite that does not have an ECHD named curve. */
    if (!namedCurve) throw new Error('Unsupported Algorithm')
    /* This is unfortunately complicated.  Node v11 crypto will accept
     * a PEM formated Buffer to sign.  But the ECDH class will still
     * return Buffers that are not PEM formated, but _only_ the points
     * on the curve.  This means I have to make a choice about
     * formating.  I chose to assume that t Buffer/Uin8Array is
     * _only_ the raw points.
     */
    if (privateKey instanceof Uint8Array) {
      const pem = privateKeyPem(namedCurve, fromBuffer(privateKey), fromBuffer(compressPoint))
      readOnlyProperty<SignatureKey, 'privateKey'>(this, 'privateKey', pem)
    } else {
      readOnlyProperty<SignatureKey, 'privateKey'>(this, 'privateKey', privateKey)
    }
    readOnlyBinaryProperty(this, 'compressPoint', compressPoint)
    Object.setPrototypeOf(this, SignatureKey.prototype)
    Object.freeze(this)
  }

  static encodeCompressPoint (publicKeyBytes: Uint8Array, suite: AlgorithmSuite) {
    const { signatureCurve: namedCurve } = suite
    /* Precondition: Do not encode a compress point for an algorithm suite that does not have an ECHD named curve. */
    if (namedCurve === void 0) throw new Error('Unsupported Algorithm')
    return encodeNamedCurves[namedCurve](publicKeyBytes)
  }
}
frozenClass(SignatureKey)

export class VerificationKey {
  public readonly publicKey!: KeyMaterial
  public readonly signatureCurve!: NodeECDHCurve|WebCryptoECDHCurve
  constructor (publicKey: KeyMaterial, suite: AlgorithmSuite) {
    const { signatureCurve: namedCurve } = suite
    /* Precondition: Do not encode a compress point for an algorithm suite that does not have an ECHD named curve. */
    if (!namedCurve) throw new Error('Unsupported Algorithm')
    /* This is unfortunately complicated.  Node v11 crypto will accept
     * a PEM formated Buffer to verify.  But the ECDH class will still
     * return Buffers that are not PEM formated, but _only_ the points
     * on the curve.  This means I have to make a choice about
     * formating.  I chose to assume that t Buffer/Uin8Array is
     * _only_ the raw points.
     */
    if (publicKey instanceof Uint8Array) {
      const pem = publicKeyPem(namedCurve, fromBuffer(publicKey))
      readOnlyProperty<VerificationKey, 'publicKey'>(this, 'publicKey', pem)
    } else {
      readOnlyProperty<VerificationKey, 'publicKey'>(this, 'publicKey', publicKey)
    }
    Object.setPrototypeOf(this, VerificationKey.prototype)
    Object.freeze(this)
  }

  static decodeCompressPoint (compressPoint: Uint8Array, suite: AlgorithmSuite) {
    const { signatureCurve: namedCurve } = suite
    /* Precondition: Do not decode a public key for an algorithm suite that does not have an ECHD named curve. */
    if (namedCurve === void 0) throw new Error('Unsupported Algorithm')

    return decodeNamedCurves[namedCurve](compressPoint)
  }
}
frozenClass(VerificationKey)

function fromBuffer (uint: Uint8Array) {
  const { buffer, byteOffset, byteLength } = uint
  return Buffer.from(buffer, byteOffset, byteLength)
}
