// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  needs,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  unwrapDataKey,
  wrapWithKeyObjectIfSupported,
  AwsEsdkKeyObject,
  NodeHash,
} from '@aws-crypto/material-management'
import {
  Signer,
  Verify,
  createCipheriv,
  createDecipheriv,
  createSign,
  createVerify,
} from 'crypto'
import { HKDF } from '@aws-crypto/hkdf-node'

export interface AwsEsdkJsCipherGCM {
  update(data: Buffer): Buffer
  final(): Buffer
  getAuthTag(): Buffer
  setAAD(aad: Buffer): this
}

export interface AwsEsdkJsDecipherGCM {
  update(data: Buffer): Buffer
  final(): Buffer
  setAuthTag(buffer: Buffer): this
  setAAD(aad: Buffer): this
}

type KDFIndex = Readonly<{ [K in NodeHash]: ReturnType<typeof HKDF> }>
const kdfIndex: KDFIndex = Object.freeze({
  sha256: HKDF('sha256' as NodeHash),
  sha384: HKDF('sha384' as NodeHash),
})

export interface GetCipher {
  (iv: Uint8Array): AwsEsdkJsCipherGCM
}

export interface CurryGetCipher {
  (info?: Uint8Array): GetCipher
}

export interface GetSigner {
  (): Signer & { awsCryptoSign: () => Buffer }
}

export interface NodeEncryptionMaterialHelper {
  kdfGetCipher: CurryGetCipher
  getSigner?: GetSigner
  dispose: () => void
}

export interface GetEncryptHelper {
  (material: NodeEncryptionMaterial): NodeEncryptionMaterialHelper
}

export const getEncryptHelper: GetEncryptHelper = (
  material: NodeEncryptionMaterial
) => {
  /* Precondition: NodeEncryptionMaterial must have a valid data key. */
  needs(material.hasValidKey(), 'Material has no unencrypted data key.')

  const { signatureHash } = material.suite
  /* Conditional types can not narrow the return type :(
   * Function overloads "works" but then I can not export
   * the function and have eslint be happy (Multiple exports of name)
   */
  const kdfGetCipher = getCryptoStream(material) as CurryGetCipher
  return Object.freeze({
    kdfGetCipher,
    getSigner: signatureHash ? getSigner : undefined,
    dispose,
  })

  function getSigner() {
    /* Precondition: The NodeEncryptionMaterial must have not been zeroed.
     * hasUnencryptedDataKey will check that the unencrypted data key has been set
     * *and* that it has not been zeroed.  At this point it must have been set
     * because the KDF function operated on it.  So at this point
     * we are protecting that someone has zeroed out the material
     * because the Encrypt process has been complete.
     */
    needs(
      material.hasUnencryptedDataKey,
      'Unencrypted data key has been zeroed.'
    )

    if (!signatureHash) throw new Error('Material does not support signature.')
    const { signatureKey } = material
    if (!signatureKey) throw new Error('Material does not support signature.')
    const { privateKey } = signatureKey
    if (typeof privateKey !== 'string')
      throw new Error('Material does not support signature.')

    const signer = Object.assign(
      createSign(signatureHash),
      // don't export the private key if we don't have to
      { awsCryptoSign: () => signer.sign(privateKey) }
    )

    return signer
  }

  function dispose() {
    material.zeroUnencryptedDataKey()
  }
}

export interface GetDecipher {
  (iv: Uint8Array): AwsEsdkJsDecipherGCM
}
export interface CurryGetDecipher {
  (info?: Uint8Array): GetDecipher
}
export interface GetVerify {
  (): Verify & { awsCryptoVerify: (signature: Buffer) => boolean }
}

export interface NodeDecryptionMaterialHelper {
  kdfGetDecipher: CurryGetDecipher
  getVerify?: GetVerify
  dispose: () => void
}

export interface GetDecryptionHelper {
  (material: NodeDecryptionMaterial): NodeDecryptionMaterialHelper
}

export const getDecryptionHelper: GetDecryptionHelper = (
  material: NodeDecryptionMaterial
) => {
  /* Precondition: NodeDecryptionMaterial must have a valid data key. */
  needs(material.hasValidKey(), 'Material has no unencrypted data key.')

  const { signatureHash } = material.suite

  /* Conditional types can not narrow the return type :(
   * Function overloads "works" but then I can not export
   * the function and have eslint be happy (Multiple exports of name)
   */
  const kdfGetDecipher = getCryptoStream(material) as CurryGetDecipher
  return Object.freeze({
    kdfGetDecipher,
    getVerify: signatureHash ? getVerify : undefined,
    dispose,
  })

  function getVerify() {
    if (!signatureHash) throw new Error('Material does not support signature.')
    const { verificationKey } = material
    if (!verificationKey)
      throw new Error('Material does not support signature.')

    const verify = Object.assign(
      createVerify(signatureHash),
      // explicitly bind the public key for this material
      {
        awsCryptoVerify: (signature: Buffer) =>
          verify.verify(verificationKey.publicKey, signature),
      }
    )

    return verify
  }

  function dispose() {
    material.zeroUnencryptedDataKey()
  }
}

export function getCryptoStream(
  material: NodeEncryptionMaterial | NodeDecryptionMaterial
) {
  const { encryption: cipherName, ivLength } = material.suite

  const createCryptoStream =
    material instanceof NodeEncryptionMaterial
      ? createCipheriv
      : material instanceof NodeDecryptionMaterial
      ? createDecipheriv
      : false

  /* Precondition: material must be either NodeEncryptionMaterial or NodeDecryptionMaterial. */
  if (!createCryptoStream)
    throw new Error('Unsupported cryptographic material.')

  return (info?: Uint8Array) => {
    const derivedKey = nodeKdf(material, info)
    return (iv: Uint8Array): AwsEsdkJsCipherGCM | AwsEsdkJsDecipherGCM => {
      /* Precondition: The length of the IV must match the NodeAlgorithmSuite specification. */
      needs(
        iv.byteLength === ivLength,
        'Iv length does not match algorithm suite specification'
      )
      /* Precondition: The material must have not been zeroed.
       * hasUnencryptedDataKey will check that the unencrypted data key has been set
       * *and* that it has not been zeroed.  At this point it must have been set
       * because the KDF function operated on it.  So at this point
       * we are protecting that someone has zeroed out the material
       * because the Encrypt process has been complete.
       */
      needs(
        material.hasUnencryptedDataKey,
        'Unencrypted data key has been zeroed.'
      )

      // createDecipheriv is incorrectly typed in @types/node. It should take key: CipherKey, not key: BinaryLike
      return createCryptoStream(cipherName, derivedKey as any, iv)
    }
  }
}

export function nodeKdf(
  material: NodeEncryptionMaterial | NodeDecryptionMaterial,
  info?: Uint8Array
): Uint8Array | AwsEsdkKeyObject {
  const dataKey = material.getUnencryptedDataKey()

  const { kdf, kdfHash, keyLengthBytes } = material.suite

  /* Check for early return (Postcondition): No Node.js KDF, just return the unencrypted data key. */
  if (!kdf && !kdfHash) return dataKey

  /* Precondition: Valid HKDF values must exist for Node.js. */
  needs(
    kdf === 'HKDF' &&
      kdfHash &&
      kdfIndex[kdfHash] &&
      info instanceof Uint8Array,
    'Invalid HKDF values.'
  )
  /* The unwrap is done once we *know* that a KDF is required.
   * If we unwrapped before everything will work,
   * but we may be creating new copies of the unencrypted data key (export).
   */
  const {
    buffer: dkBuffer,
    byteOffset: dkByteOffset,
    byteLength: dkByteLength,
  } = unwrapDataKey(dataKey)
  // info and kdfHash are now defined
  const toExtract = Buffer.from(dkBuffer, dkByteOffset, dkByteLength)
  const { buffer, byteOffset, byteLength } = info as Uint8Array
  const infoBuff = Buffer.from(buffer, byteOffset, byteLength)

  const derivedBytes = kdfIndex[kdfHash as NodeHash](toExtract)(
    keyLengthBytes,
    infoBuff
  )

  return wrapWithKeyObjectIfSupported(derivedBytes)
}
