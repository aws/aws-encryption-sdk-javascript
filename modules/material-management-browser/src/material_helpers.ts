// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  needs,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  isCryptoKey,
  isValidCryptoKey,
  keyUsageForMaterial,
  unwrapDataKey,
  AwsEsdkJsCryptoKey,
  WebCryptoMaterial,
  SupportedAlgorithmSuites,
} from '@aws-crypto/material-management'
import {
  kdfInfo,
  kdfCommitKeyInfo,
  MessageIdLength,
} from '@aws-crypto/serialize'

import {
  getWebCryptoBackend,
  getNonZeroByteBackend,
  getZeroByteSubtle,
  isFullSupportWebCryptoBackend,
  WebCryptoBackend,
} from '@aws-crypto/web-crypto-backend'

import { bytes2JWK } from './bytes2_jwk'

export interface GetSubtleEncrypt {
  (iv: Uint8Array, additionalData: Uint8Array): (
    data: Uint8Array
  ) => Promise<ArrayBuffer>
}

interface EncryptInfo {
  getSubtleEncrypt: GetSubtleEncrypt
  keyCommitment?: Uint8Array
}

export interface GetEncryptInfo {
  (messageId: Uint8Array): Promise<EncryptInfo>
}

export interface SubtleSign {
  (data: Uint8Array): PromiseLike<ArrayBuffer>
}

export interface WebCryptoEncryptionMaterialHelper {
  getEncryptInfo: GetEncryptInfo
  subtleSign?: SubtleSign
  dispose: () => void
}

export interface GetEncryptHelper {
  (
    material: WebCryptoEncryptionMaterial
  ): Promise<WebCryptoEncryptionMaterialHelper>
}

export const getEncryptHelper: GetEncryptHelper = async (
  material: WebCryptoEncryptionMaterial
) => {
  const backend = await getWebCryptoBackend()

  /* Precondition: WebCryptoEncryptionMaterial must have a valid data key. */
  needs(material.hasValidKey(), 'Material has no CryptoKey.')

  const { signatureHash } = material.suite
  const getEncryptInfo = currySubtleFunction(material, backend, 'encrypt')
  return Object.freeze({
    getEncryptInfo,
    subtleSign: signatureHash ? getSubtleSign : undefined,
    dispose,
  })

  async function getSubtleSign(data: Uint8Array) {
    if (!signatureHash)
      throw new Error('Algorithm suite does not support signing.')
    const { signatureKey } = material
    if (!signatureKey) throw new Error('Malformed Material.')
    const { privateKey } = signatureKey
    if (!isCryptoKey(privateKey)) throw new Error('Malformed Material.')
    const algorithm = { name: 'ECDSA', hash: { name: signatureHash } }
    return getNonZeroByteBackend(backend).sign(algorithm, privateKey, data)
  }

  function dispose() {
    material.zeroUnencryptedDataKey()
  }
}

export interface GetSubtleDecrypt extends GetSubtleEncrypt {}

export interface GetDecryptInfo {
  (messageId: Uint8Array, commitKey?: Uint8Array): Promise<GetSubtleDecrypt>
}

interface SubtleVerify {
  (signature: Uint8Array, data: Uint8Array): PromiseLike<boolean>
}

export interface WebCryptoDecryptionMaterialHelper {
  getDecryptInfo: GetDecryptInfo
  subtleVerify?: SubtleVerify
  dispose: () => void
}

export interface GetDecryptionHelper {
  (
    material: WebCryptoDecryptionMaterial
  ): Promise<WebCryptoDecryptionMaterialHelper>
}

export const getDecryptionHelper: GetDecryptionHelper = async (
  material: WebCryptoDecryptionMaterial
) => {
  const backend = await getWebCryptoBackend()

  /* Precondition: WebCryptoDecryptionMaterial must have a valid data key. */
  needs(material.hasValidKey(), 'Material has no valid data key.')

  const { signatureHash } = material.suite
  const getDecryptInfo = currySubtleFunction(material, backend, 'decrypt')

  return Object.freeze({
    getDecryptInfo,
    subtleVerify: signatureHash ? subtleVerify : undefined,
    dispose,
  })

  async function subtleVerify(signature: Uint8Array, data: Uint8Array) {
    if (!signatureHash)
      throw new Error('Algorithm suite does not support signing.')
    const { verificationKey } = material
    if (!verificationKey) throw new Error('Malformed Material.')
    const { publicKey } = verificationKey
    if (!isCryptoKey(publicKey)) throw new Error('Malformed Material.')
    const algorithm = { name: 'ECDSA', hash: { name: signatureHash } }
    return getNonZeroByteBackend(backend).verify(
      algorithm,
      publicKey,
      signature,
      data
    )
  }

  function dispose() {
    material.zeroUnencryptedDataKey()
  }
}

type SubtleFunctionName = 'encrypt' | 'decrypt'

type PickSubtleReturn<T extends SubtleFunctionName> = T extends 'encrypt'
  ? {
      getSubtleEncrypt: GetSubtleEncrypt
      keyCommitment?: Uint8Array
    }
  : GetSubtleDecrypt

export function currySubtleFunction<
  Material extends WebCryptoMaterial<Material>,
  Name extends SubtleFunctionName
>(material: Material, backend: WebCryptoBackend, subtleFunctionName: Name) {
  /* Precondition: The material must have a CryptoKey. */
  needs(material.hasCryptoKey, 'Material must have a CryptoKey.')

  const cryptoKey = material.getCryptoKey()

  /* Precondition: The cryptoKey and backend must match in terms of Mixed vs Full support. */
  needs(
    isCryptoKey(cryptoKey) === isFullSupportWebCryptoBackend(backend),
    'CryptoKey vs WebCrypto backend mismatch.'
  )
  const { suite } = material
  const { encryption: cipherName, ivLength, tagLength } = suite

  return async (messageId: Uint8Array, commitKey?: Uint8Array) => {
    /* This is very strange.
     * I would expect that I could await
     * the ternary and all would be fine.
     * But in testing, wallaby.js+webpack
     * compiles the typescript in such a way
     * that `deriveKey` is still
     * a promise by the time it gets to
     * the `data` below.
     * So I add awaits on the individual elements.
     */
    const { deriveKey, keyCommitment } = isCryptoKey(cryptoKey)
      ? await WebCryptoKdf(
          getNonZeroByteBackend(backend),
          material,
          cryptoKey,
          [subtleFunctionName],
          messageId,
          commitKey
        )
      : await Promise.all([
          WebCryptoKdf(
            getNonZeroByteBackend(backend),
            material,
            cryptoKey.nonZeroByteCryptoKey,
            [subtleFunctionName],
            messageId,
            commitKey
          ),
          WebCryptoKdf(
            getZeroByteSubtle(backend),
            material,
            cryptoKey.zeroByteCryptoKey,
            [subtleFunctionName],
            messageId,
            commitKey
          ),
        ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({
          deriveKey: {
            nonZeroByteCryptoKey: nonZeroByteCryptoKey.deriveKey,
            zeroByteCryptoKey: zeroByteCryptoKey.deriveKey,
          },
          /* This works *because* the commitKey
           * that is passed to both zero and nonzero is the same.
           * If that ever changed, this might no longer be true.
           */
          keyCommitment: nonZeroByteCryptoKey.keyCommitment,
        }))

    return (
      subtleFunctionName === 'encrypt'
        ? { getSubtleEncrypt: getSubtleFunction, keyCommitment }
        : getSubtleFunction
    ) as PickSubtleReturn<Name>

    function getSubtleFunction(iv: Uint8Array, additionalData: Uint8Array) {
      /* Precondition: The length of the IV must match the WebCryptoAlgorithmSuite specification. */
      needs(
        iv.byteLength === ivLength,
        'Iv length does not match algorithm suite specification'
      )
      return async (data: Uint8Array) => {
        if (isCryptoKey(deriveKey) && isFullSupportWebCryptoBackend(backend)) {
          const { subtle } = backend
          const algorithm = { name: cipherName, iv, additionalData, tagLength }
          return subtle[subtleFunctionName](algorithm, deriveKey, data)
        } else if (
          !isCryptoKey(deriveKey) &&
          !isFullSupportWebCryptoBackend(backend)
        ) {
          const { nonZeroByteSubtle, zeroByteSubtle } = backend
          const { nonZeroByteCryptoKey, zeroByteCryptoKey } = deriveKey
          const algorithm = { name: cipherName, iv, additionalData, tagLength }
          /* Precondition: The WebCrypto AES-GCM decrypt API expects the data *and* tag together.
           * This means that on decrypt any amount of data less than tagLength is invalid.
           * This also means that zero encrypted data will be equal to tagLength.
           */
          const dataByteLength =
            subtleFunctionName === 'decrypt'
              ? data.byteLength - tagLength / 8
              : data.byteLength
          needs(dataByteLength >= 0, 'Invalid data length.')
          if (dataByteLength === 0) {
            return zeroByteSubtle[subtleFunctionName](
              algorithm,
              zeroByteCryptoKey,
              data
            )
          } else {
            return nonZeroByteSubtle[subtleFunctionName](
              algorithm,
              nonZeroByteCryptoKey,
              data
            )
          }
        }
        // This should be impossible
        throw new Error('Unknown Error')
      }
    }
  }
}

export async function WebCryptoKdf<T extends WebCryptoMaterial<T>>(
  subtle: SubtleCrypto,
  material: T,
  cryptoKey: AwsEsdkJsCryptoKey,
  keyUsages: SubtleFunctionName[],
  nonce: Uint8Array,
  commitKey?: Uint8Array
): Promise<{ deriveKey: AwsEsdkJsCryptoKey; keyCommitment?: Uint8Array }> {
  const { kdf, kdfHash, keyLength, encryption } = material.suite

  /* Check for early return (Postcondition): No WebCrypto KDF, just return the unencrypted data key. */
  if (!kdf && !kdfHash) return { deriveKey: cryptoKey }

  const keyCommitment = await deriveKeyCommitment(
    subtle,
    material,
    cryptoKey,
    nonce,
    commitKey
  )

  // https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams
  const kdfAlgorithm = buildAlgorithmForKDF(material.suite, nonce)
  const derivedKeyAlgorithm = { name: encryption, length: keyLength }
  const extractable = false
  const deriveKey = await subtle.deriveKey(
    // types need to be updated see: https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams
    kdfAlgorithm,
    cryptoKey,
    derivedKeyAlgorithm,
    extractable,
    keyUsages
  )
  /* Postcondition: The derived key must conform to the algorith suite specification. */
  needs(isValidCryptoKey(deriveKey, material), 'Invalid derived key')
  return { deriveKey, keyCommitment }
}

export function buildAlgorithmForKDF(
  suite: SupportedAlgorithmSuites,
  nonce: Uint8Array
) {
  const { kdf, kdfHash, commitmentLength, saltLengthBytes } = suite

  /* Precondition: Valid HKDF values must exist for browsers. */
  needs(
    kdf === 'HKDF' && kdfHash && nonce instanceof Uint8Array,
    'Invalid HKDF values.'
  )

  if (suite.commitment === 'NONE') {
    /* Precondition: The message ID length must match the specification. */
    needs(
      nonce.byteLength === MessageIdLength.V1,
      'Message id length does not match specification.'
    )
    const info = kdfInfo(suite.id, nonce)
    // https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams
    return {
      name: kdf,
      hash: { name: kdfHash },
      info,
      salt: new Uint8Array(),
    }
  }

  /* Precondition UNTESTED: The suite must be well structured. */
  needs(
    suite.commitment === 'KEY' && commitmentLength && saltLengthBytes,
    'Malformed suite data.'
  )

  /* Precondition: The message id length must match the algorithm suite.
   * I am using the message id here,
   * but I must have enough entropy!
   */
  needs(
    nonce.byteLength === saltLengthBytes,
    'Message id length does not match specification.'
  )

  const { keyLabel: info } = kdfCommitKeyInfo(suite)
  const salt = nonce

  // https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams
  return {
    name: kdf,
    hash: { name: kdfHash },
    info,
    salt,
  }
}

export async function deriveKeyCommitment<T extends WebCryptoMaterial<T>>(
  subtle: SubtleCrypto,
  material: T,
  cryptoKey: AwsEsdkJsCryptoKey,
  nonce: Uint8Array,
  commitKey?: Uint8Array
): Promise<Uint8Array | undefined> {
  const { suite } = material
  const { kdf, kdfHash, commitmentLength, saltLengthBytes, commitment } = suite

  /* Check for early return (Postcondition): Algorithm suites without commitment do not have a commitment. */
  if (commitment === 'NONE') {
    /* Postcondition: Non-committing WebCrypto algorithm suites *must* not have a commitment. */
    needs(!commitKey, 'Commitment not supported.')
    return
  }

  /* Precondition UNTESTED: Only support key commitment. */
  needs(
    commitment === 'KEY' && commitmentLength && saltLengthBytes,
    'Malformed suite data.'
  )

  /* Precondition: Commit key requires 256 bits of entropy. */
  needs(
    nonce.byteLength === saltLengthBytes,
    'Nonce is not the correct length for committed algorithm suite.'
  )

  /* Precondition UNTESTED: Valid HKDF values must exist for commit key. */
  needs(
    kdf === 'HKDF' && kdfHash && nonce instanceof Uint8Array,
    'Invalid HKDF values.'
  )

  const { commitLabel: info } = kdfCommitKeyInfo(material.suite)

  /* In a more perfect world,
   * I would use `deriveBits`.
   * However I _know_ that deriveKey exists,
   * and is already used everywhere.
   * This is ugly here,
   * but is less churn to write today.
   * Also, deriveKey is slightly safer
   * for the actual key used.
   * Since both the commit key
   * and the kdf key come from the same root,
   * I *must* give this permission
   * to this root key.
   * This means that if the root key has `deriveBits`,
   * then I have effectively given `export`
   * to the operational derived key.
   * Because while the root key can not be exported,
   * the derived key could.
   * This is a thin reason, because you could just
   * create your own exportable key,
   * but, every little bit helps.
   */
  const keyCommitAlgorithm = {
    name: kdf,
    hash: { name: kdfHash },
    info,
    salt: nonce,
  }
  const derivedKeyAlgorithm = {
    name: suite.encryption,
    length: commitmentLength,
  }
  const extractable = true
  const deriveKey = await subtle.deriveKey(
    // types need to be updated see: https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams
    keyCommitAlgorithm,
    cryptoKey,
    derivedKeyAlgorithm,
    extractable,
    /* Something has to go here. */
    ['encrypt']
  )
  const keyCommitment = new Uint8Array(await subtle.exportKey('raw', deriveKey))

  const isDecrypt = material instanceof WebCryptoDecryptionMaterial
  /* Precondition: If material is WebCryptoDecryptionMaterial the key commitments *must* match.
   * Ideally this will be checked _before_ the data key is derived
   * because then the decryption key is never even derived.
   * But for WebCrypto this is a bit hard,
   * because of legacy browsers and the lack of zero byte support.
   */
  needs(
    (isDecrypt &&
      commitKey &&
      portableTimingSafeEqual(commitKey, keyCommitment)) ||
      (!isDecrypt && !commitKey),
    isDecrypt ? 'Commitment does not match.' : 'Invalid arguments.'
  )

  return keyCommitment
}

export async function importCryptoKey<T extends WebCryptoMaterial<T>>(
  backend: WebCryptoBackend,
  material: T,
  keyUsages: KeyUsage[] = [keyUsageForMaterial(material)]
) {
  if (isFullSupportWebCryptoBackend(backend)) {
    return _importCryptoKey(backend.subtle, material, keyUsages)
  } else {
    return Promise.all([
      _importCryptoKey(getNonZeroByteBackend(backend), material, keyUsages),
      _importCryptoKey(getZeroByteSubtle(backend), material, keyUsages),
    ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({
      nonZeroByteCryptoKey,
      zeroByteCryptoKey,
    }))
  }
}

export async function _importCryptoKey<T extends WebCryptoMaterial<T>>(
  subtle: SubtleCrypto,
  material: T,
  keyUsages: KeyUsage[] = [keyUsageForMaterial(material)]
): Promise<AwsEsdkJsCryptoKey> {
  const { suite } = material
  const extractable = false
  const udk = unwrapDataKey(material.getUnencryptedDataKey())

  if (suite.kdf) {
    /* For several browsers, import for a key to derive with HKDF
     * *must* be raw.  This may cause some compatibility issues
     * with browsers that need a zero byte gcm fallback.
     */
    const format = 'raw'
    const algorithm = { name: suite.kdf, length: suite.keyLength }
    return subtle.importKey(format, udk, algorithm, extractable, keyUsages)
  } else {
    const format = 'jwk'
    const algorithm = { name: suite.encryption, length: suite.keyLength }
    const jwk = bytes2JWK(udk)
    return subtle.importKey(format, jwk, algorithm, extractable, keyUsages)
  }
}

function portableTimingSafeEqual(a: Uint8Array, b: Uint8Array) {
  /* It is *possible* that a runtime could optimize this constant time function.
   * Adding `eval` could prevent the optimization, but this is no guarantee.
   * The eval below is commented out
   * because if a browser is using a Content Security Policy with `'unsafe-eval'`
   * it would fail on this eval.
   * The value in attempting to ensure that this function is not optimized
   * is not worth the cost of making customers allow `'unsafe-eval'`.
   * If you want to copy this function for your own use,
   * please review the timing-attack link above.
   * Side channel attacks are pernicious and subtle.
   */
  // eval('') // eslint-disable-line no-eval
  /* Check for early return (Postcondition) UNTESTED: Size is well-know information
   * and does not leak information about contents.
   */
  if (a.byteLength !== b.byteLength) return false

  let diff = 0
  for (let i = 0; i < b.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return diff === 0
}
