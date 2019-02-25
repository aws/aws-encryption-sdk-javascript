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

import { AlgorithmSuite } from './algorithm_suites' // eslint-disable-line no-unused-vars
import { encodeNamedCurves } from './ecc_encode'
import { decodeNamedCurves } from './ecc_decode'
import { frozenClass, readOnlyBinaryProperty, readOnlyProperty } from './immutable_class'

/*
 * This public interface to the SignatureKey object is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */

type KeyMaterial = Uint8Array|CryptoKey

export class SignatureKey {
  public readonly privateKey!: KeyMaterial
  public readonly compressPoint!: Uint8Array
  constructor (privateKey: KeyMaterial, compressPoint: Uint8Array) {
    if (privateKey instanceof Uint8Array) {
      readOnlyBinaryProperty(this, 'privateKey', privateKey)
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
  constructor (publicKey: KeyMaterial) {
    if (publicKey instanceof Uint8Array) {
      readOnlyBinaryProperty(this, 'publicKey', publicKey)
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
