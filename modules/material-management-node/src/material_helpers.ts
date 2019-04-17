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

import {
  needs, NodeEncryptionMaterial, NodeDecryptionMaterial,
  NodeHash // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'
import {
  CipherGCM, DecipherGCM, Verify, // eslint-disable-line no-unused-vars
  createCipheriv, createDecipheriv, createVerify
} from 'crypto'
import { HKDF } from '@aws-crypto/hkdf-node'
import {
  createFixedLengthECDSASign,
  FixedLengthECDSASign // eslint-disable-line no-unused-vars
} from './fixed_length_ecdsa_sign'

type KDFIndex = Readonly<{[K in NodeHash]: ReturnType<typeof HKDF>}>
const kdfIndex: KDFIndex = Object.freeze({
  sha256: HKDF('sha256' as NodeHash),
  sha384: HKDF('sha384' as NodeHash)
})

export interface GetCipher {
  (info?: Uint8Array) : (iv: Uint8Array) => CipherGCM
}

export interface GetSigner {
  () : FixedLengthECDSASign & {awsCryptoSign: () => Buffer}
}

export interface NodeEncryptionMaterialHelper {
  kdfGetCipher: GetCipher
  getSigner?: GetSigner
  dispose: () => void
}

export interface GetEncryptHelper {
  (material: NodeEncryptionMaterial) : NodeEncryptionMaterialHelper
}

export const getEncryptHelper: GetEncryptHelper = (material: NodeEncryptionMaterial) => {
  /* Precondition: NodeEncryptionMaterial must have a valid data key. */
  needs(material.hasValidKey(), 'Material has no unencrypted data key.')

  const { signatureCurve } = material.suite
  /* Conditional types can not narrow the return type :(
   * Function overloads "works" but then I can not export
   * the function and have eslint be happy (Multiple exports of name)
   */
  const kdfGetCipher = <GetCipher>getCryptoStream(material)
  return Object.freeze({
    kdfGetCipher,
    getSigner: signatureCurve ? getSigner : undefined,
    dispose
  })

  function getSigner () {
    /* Precondition: The NodeEncryptionMaterial must have not been zeroed.
     * hasUnencryptedDataKey will check that the unencrypted data key has been set
     * *and* that it has not been zeroed.  At this point it must have been set
     * because the KDF function operated on it.  So at this point
     * we are protecting that someone has zeroed out the material
     * because the Encrypt process has been complete.
     */
    needs(material.hasUnencryptedDataKey, 'Unencrypted data key has been zeroed.')

    if (!signatureCurve) throw new Error('Material does not support signature.')
    const { signatureKey } = material
    if (!signatureKey) throw new Error('Material does not support signature.')
    const { privateKey } = signatureKey
    if (typeof privateKey !== 'string') throw new Error('Material does not support signature.')

    const signer = Object.assign(
      createFixedLengthECDSASign(signatureCurve),
      // don't export the private key if we don't have to
      { awsCryptoSign: () => signer.sign(privateKey) })

    return signer
  }

  function dispose () {
    material.zeroUnencryptedDataKey()
  }
}

export interface GetDecipher {
  (info?: Uint8Array) : (iv: Uint8Array) => DecipherGCM
}
export interface GetVerify {
  () : Verify & {awsCryptoVerify: (signature: Buffer) => boolean}
}

export interface NodeDecryptionMaterialHelper {
  kdfGetDecipher: GetDecipher
  getVerify?: GetVerify
  dispose: () => void
}

export interface GetDecryptionHelper {
  (material: NodeDecryptionMaterial) : NodeDecryptionMaterialHelper
}

export const getDecryptionHelper: GetDecryptionHelper = (material: NodeDecryptionMaterial) => {
  /* Precondition: NodeDecryptionMaterial must have a valid data key. */
  needs(material.hasValidKey(), 'Material has no unencrypted data key.')

  const { signatureHash } = material.suite

  /* Conditional types can not narrow the return type :(
   * Function overloads "works" but then I can not export
   * the function and have eslint be happy (Multiple exports of name)
   */
  const kdfGetDecipher = <GetDecipher>getCryptoStream(material)
  return Object.freeze({
    kdfGetDecipher,
    getVerify: signatureHash ? getVerify : undefined,
    dispose
  })

  function getVerify () {
    if (!signatureHash) throw new Error('Material does not support signature.')
    const { verificationKey } = material
    if (!verificationKey) throw new Error('Material does not support signature.')

    const verify = Object.assign(
      createVerify(signatureHash),
      // explicitly bind the public key for this material
      { awsCryptoVerify: (signature: Buffer) => verify.verify(verificationKey.publicKey, signature) })

    return verify
  }

  function dispose () {
    material.zeroUnencryptedDataKey()
  }
}

export function getCryptoStream (material: NodeEncryptionMaterial|NodeDecryptionMaterial) {
  const { encryption: cipherName, ivLength } = material.suite

  const createCryptoStream = material instanceof NodeEncryptionMaterial
    ? createCipheriv
    : material instanceof NodeDecryptionMaterial
      ? createDecipheriv
      : false

  /* Precondition: material must be either NodeEncryptionMaterial or NodeDecryptionMaterial. */
  if (!createCryptoStream) throw new Error('Unsupported cryptographic material.')

  return (info?: Uint8Array) => {
    const derivedKey = nodeKdf(material, info)
    return (iv: Uint8Array) => {
      /* Precondition: The length of the IV must match the algorithm suite specification. */
      needs(iv.byteLength === ivLength, 'Iv length does not match algorithm suite specification')
      /* Precondition: The material must have not been zeroed.
      * hasUnencryptedDataKey will check that the unencrypted data key has been set
      * *and* that it has not been zeroed.  At this point it must have been set
      * because the KDF function operated on it.  So at this point
      * we are protecting that someone has zeroed out the material
      * because the Encrypt process has been complete.
      */
      needs(material.hasUnencryptedDataKey, 'Unencrypted data key has been zeroed.')

      return createCryptoStream(cipherName, derivedKey, iv)
    }
  }
}

export function nodeKdf (material: NodeEncryptionMaterial|NodeDecryptionMaterial, info?: Uint8Array): Uint8Array {
  const dataKey = material.getUnencryptedDataKey()

  const { kdf, kdfHash, keyLengthBytes } = material.suite

  /* Check for early return (Postcondition): No KDF, just return the unencrypted data key. */
  if (!kdf) return dataKey

  /* Precondition: Valid HKDF values must exist. */
  needs(
    kdf === 'HKDF' &&
    kdfHash &&
    kdfIndex[kdfHash] &&
    info instanceof Uint8Array,
    ''
  )
  // info and kdfHash are now defined
  const toExtract = Buffer.from(dataKey.buffer, dataKey.byteOffset, dataKey.byteLength)
  const { buffer, byteOffset, byteLength } = <Uint8Array> info
  const infoBuff = Buffer.from(buffer, byteOffset, byteLength)

  return kdfIndex[<NodeHash>kdfHash](toExtract)(keyLengthBytes, infoBuff)
}
