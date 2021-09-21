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
  timingSafeEqual,
} from 'crypto'
import { HKDF } from '@aws-crypto/hkdf-node'
import { kdfInfo, kdfCommitKeyInfo } from '@aws-crypto/serialize'

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
  sha512: HKDF('sha512' as NodeHash),
})

export interface GetCipher {
  (iv: Uint8Array): AwsEsdkJsCipherGCM
}

export interface GetCipherInfo {
  (messageId: Uint8Array): {
    getCipher: GetCipher
    keyCommitment?: Uint8Array
  }
}

export interface GetSigner {
  (): Signer & { awsCryptoSign: () => Buffer }
}

export interface NodeEncryptionMaterialHelper {
  getCipherInfo: GetCipherInfo
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
  const getCipherInfo = curryCryptoStream(material, createCipheriv)
  return Object.freeze({
    getCipherInfo,
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
export interface GetDecipherInfo {
  (messageId: Uint8Array, commitKey?: Uint8Array): GetDecipher
}

export interface GetVerify {
  (): Verify & { awsCryptoVerify: (signature: Buffer) => boolean }
}

export interface NodeDecryptionMaterialHelper {
  getDecipherInfo: GetDecipherInfo
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
  const getDecipherInfo = curryCryptoStream(material, createDecipheriv)
  return Object.freeze({
    getDecipherInfo,
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
          // As typescript gets better typing
          // We should consider either generics or
          // 2 different verificationKeys for Node and WebCrypto
          verify.verify(verificationKey.publicKey as string, signature),
      }
    )

    return verify
  }

  function dispose() {
    material.zeroUnencryptedDataKey()
  }
}

type CreateCryptoIvStream<
  Material extends NodeEncryptionMaterial | NodeDecryptionMaterial
> = Material extends NodeEncryptionMaterial
  ? typeof createCipheriv
  : typeof createDecipheriv

type CryptoStream<
  Material extends NodeEncryptionMaterial | NodeDecryptionMaterial
> = Material extends NodeEncryptionMaterial
  ? AwsEsdkJsCipherGCM
  : AwsEsdkJsDecipherGCM

type CreateCryptoStream<
  Material extends NodeEncryptionMaterial | NodeDecryptionMaterial
> = (iv: Uint8Array) => CryptoStream<Material>

type CurryHelper<
  Material extends NodeEncryptionMaterial | NodeDecryptionMaterial
> = Material extends NodeEncryptionMaterial
  ? {
      getCipher: CreateCryptoStream<Material>
      keyCommitment: Uint8Array
    }
  : Material extends NodeDecryptionMaterial
  ? CreateCryptoStream<Material>
  : never

export function curryCryptoStream<
  Material extends NodeEncryptionMaterial | NodeDecryptionMaterial
>(material: Material, createCryptoIvStream: CreateCryptoIvStream<Material>) {
  const { encryption: cipherName, ivLength } = material.suite

  const isEncrypt = material instanceof NodeEncryptionMaterial
  /* Precondition: material must be either NodeEncryptionMaterial or NodeDecryptionMaterial.
   *
   */
  needs(
    isEncrypt
      ? createCipheriv === createCryptoIvStream
      : material instanceof NodeDecryptionMaterial
      ? createDecipheriv === createCryptoIvStream
      : false,
    'Unsupported cryptographic material.'
  )

  return (messageId: Uint8Array, commitKey?: Uint8Array) => {
    const { derivedKey, keyCommitment } = nodeKdf(
      material,
      messageId,
      commitKey
    )

    return (
      isEncrypt
        ? { getCipher: createCryptoStream, keyCommitment }
        : createCryptoStream
    ) as CurryHelper<Material>

    function createCryptoStream(iv: Uint8Array): CryptoStream<Material> {
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

      /* createDecipheriv is incorrectly typed in @types/node. It should take key: CipherKey, not key: BinaryLike.
       * Also, the check above ensures
       * that _createCryptoStream is not false.
       * But TypeScript does not believe me.
       * For any complicated code,
       * you should defer to the checker,
       * but here I'm going to assert
       * it is simple enough.
       */
      return createCryptoIvStream(
        cipherName,
        derivedKey as any,
        iv
      ) as unknown as CryptoStream<Material>
    }
  }
}

export function nodeKdf(
  material: NodeEncryptionMaterial | NodeDecryptionMaterial,
  nonce: Uint8Array,
  commitKey?: Uint8Array
): {
  derivedKey: Uint8Array | AwsEsdkKeyObject
  keyCommitment?: Uint8Array
} {
  const dataKey = material.getUnencryptedDataKey()

  const {
    kdf,
    kdfHash,
    keyLengthBytes,
    commitmentLength,
    saltLengthBytes,
    commitment,
    id: suiteId,
  } = material.suite

  /* Check for early return (Postcondition): No Node.js KDF, just return the unencrypted data key. */
  if (!kdf && !kdfHash) {
    /* Postcondition: Non-KDF algorithm suites *must* not have a commitment. */
    needs(!commitKey, 'Commitment not supported.')
    return { derivedKey: dataKey }
  }

  /* Precondition: Valid HKDF values must exist for Node.js. */
  needs(
    kdf === 'HKDF' &&
      kdfHash &&
      kdfIndex[kdfHash] &&
      nonce instanceof Uint8Array,
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

  if (commitment === 'NONE') {
    /* Postcondition: Non-committing Node algorithm suites *must* not have a commitment. */
    needs(!commitKey, 'Commitment not supported.')

    const toExtract = Buffer.from(dkBuffer, dkByteOffset, dkByteLength)
    const { buffer, byteOffset, byteLength } = kdfInfo(suiteId, nonce)
    const infoBuff = Buffer.from(buffer, byteOffset, byteLength)

    const derivedBytes = kdfIndex[kdfHash as NodeHash](toExtract)(
      keyLengthBytes,
      infoBuff
    )
    const derivedKey = wrapWithKeyObjectIfSupported(derivedBytes)

    return { derivedKey }
  }

  /* Precondition UNTESTED: Committing suites must define expected values. */
  needs(
    commitment === 'KEY' && commitmentLength && saltLengthBytes,
    'Malformed suite data.'
  )
  /* Precondition: For committing algorithms, the nonce *must* be 256 bit.
   * i.e. It must target a V2 message format.
   */
  needs(
    nonce.byteLength === saltLengthBytes,
    'Nonce is not the correct length for committed algorithm suite.'
  )

  const toExtract = Buffer.from(dkBuffer, dkByteOffset, dkByteLength)
  const expand = kdfIndex[kdfHash as NodeHash](toExtract, nonce)

  const { keyLabel, commitLabel } = kdfCommitKeyInfo(material.suite)
  const keyCommitment = expand(commitmentLength / 8, commitLabel)

  const isDecrypt = material instanceof NodeDecryptionMaterial
  /* Precondition: If material is NodeDecryptionMaterial the key commitments *must* match.
   * This is also the preferred location to check,
   * because then the decryption key is never even derived.
   */
  needs(
    (isDecrypt && commitKey && timingSafeEqual(keyCommitment, commitKey)) ||
      (!isDecrypt && !commitKey),
    isDecrypt ? 'Commitment does not match.' : 'Invalid arguments.'
  )

  const derivedBytes = expand(keyLengthBytes, keyLabel)
  const derivedKey = wrapWithKeyObjectIfSupported(derivedBytes)
  return { derivedKey, keyCommitment }
}
