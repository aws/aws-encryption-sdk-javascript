// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AlgorithmSuite,
  NodeECDHCurve,
  WebCryptoECDHCurve,
} from './algorithm_suites'
import { encodeNamedCurves } from './ecc_encode'
import { decodeNamedCurves } from './ecc_decode'
import {
  frozenClass,
  readOnlyBinaryProperty,
  readOnlyProperty,
} from './immutable_class'
import { publicKeyPem, privateKeyPem } from './pem_helpers'
import { AwsEsdkJsCryptoKey } from './types'

/*
 * This public interface to the SignatureKey object is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */

export class SignatureKey {
  public declare readonly privateKey: string | AwsEsdkJsCryptoKey
  public declare readonly compressPoint: Uint8Array
  public declare readonly signatureCurve: NodeECDHCurve | WebCryptoECDHCurve
  constructor(
    privateKey: Uint8Array | AwsEsdkJsCryptoKey,
    compressPoint: Uint8Array,
    suite: AlgorithmSuite
  ) {
    const { signatureCurve: namedCurve } = suite
    /* Precondition: Do not create a SignatureKey for an algorithm suite that does not have an EC named curve. */
    if (!namedCurve) throw new Error('Unsupported Algorithm')
    /* This is unfortunately complicated.  Node v11 crypto will accept
     * a PEM formated Buffer to sign.  But the ECDH class will still
     * return Buffers that are not PEM formated, but _only_ the points
     * on the curve.  This means I have to make a choice about
     * formating.  I chose to assume that t Buffer/Uin8Array is
     * _only_ the raw points.
     */
    if (privateKey instanceof Uint8Array) {
      const pem = privateKeyPem(
        namedCurve,
        fromBuffer(privateKey),
        fromBuffer(compressPoint)
      )
      readOnlyProperty<SignatureKey, 'privateKey'>(this, 'privateKey', pem)
    } else {
      readOnlyProperty<SignatureKey, 'privateKey'>(
        this,
        'privateKey',
        privateKey
      )
    }
    readOnlyBinaryProperty(this, 'compressPoint', compressPoint)
    readOnlyProperty(this, 'signatureCurve', namedCurve)
    Object.setPrototypeOf(this, SignatureKey.prototype)
    Object.freeze(this)
  }

  static encodeCompressPoint(
    publicKeyBytes: Uint8Array,
    suite: AlgorithmSuite
  ) {
    const { signatureCurve: namedCurve } = suite
    /* Precondition: Do not return a compress point for an algorithm suite that does not have an EC named curve. */
    if (!namedCurve) throw new Error('Unsupported Algorithm')
    return encodeNamedCurves[namedCurve](publicKeyBytes)
  }
}
frozenClass(SignatureKey)

export class VerificationKey {
  public readonly publicKey!: string | AwsEsdkJsCryptoKey
  public readonly signatureCurve!: NodeECDHCurve | WebCryptoECDHCurve
  constructor(
    publicKey: Uint8Array | AwsEsdkJsCryptoKey,
    suite: AlgorithmSuite
  ) {
    const { signatureCurve: namedCurve } = suite
    /* Precondition: Do not create a VerificationKey for an algorithm suite that does not have an EC named curve. */
    if (!namedCurve) throw new Error('Unsupported Algorithm')
    /* This is unfortunately complicated.  Node v11 crypto will accept
     * a PEM formated Buffer to verify.  But the ECDH class will still
     * return Buffers that are not PEM formated, but _only_ the points
     * on the curve.  This means I have to make a choice about
     * formating.  I chose to assume that the Buffer/Uin8Array is
     * _only_ the raw points.
     */
    if (publicKey instanceof Uint8Array) {
      const pem = publicKeyPem(namedCurve, fromBuffer(publicKey))
      readOnlyProperty<VerificationKey, 'publicKey'>(this, 'publicKey', pem)
    } else {
      readOnlyProperty<VerificationKey, 'publicKey'>(
        this,
        'publicKey',
        publicKey
      )
    }
    readOnlyProperty(this, 'signatureCurve', namedCurve)
    Object.setPrototypeOf(this, VerificationKey.prototype)
    Object.freeze(this)
  }

  static decodeCompressPoint(compressPoint: Uint8Array, suite: AlgorithmSuite) {
    const { signatureCurve: namedCurve } = suite
    /* Precondition: Do not decode a public key for an algorithm suite that does not have an EC named curve. */
    if (!namedCurve) throw new Error('Unsupported Algorithm')

    return decodeNamedCurves[namedCurve](compressPoint)
  }
}
frozenClass(VerificationKey)

function fromBuffer(uint: Uint8Array) {
  const { buffer, byteOffset, byteLength } = uint
  return Buffer.from(buffer, byteOffset, byteLength)
}
