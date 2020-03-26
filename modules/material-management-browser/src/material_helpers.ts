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
  needs,
  WebCryptoEncryptionMaterial, // eslint-disable-line no-unused-vars
  WebCryptoDecryptionMaterial, // eslint-disable-line no-unused-vars
  MixedBackendCryptoKey, // eslint-disable-line no-unused-vars
  isCryptoKey,
  isValidCryptoKey,
  keyUsageForMaterial,
  subtleFunctionForMaterial,
  unwrapDataKey,
  AwsEsdkJsCryptoKey, // eslint-disable-line no-unused-vars
  WebCryptoMaterial // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'

import {
  getWebCryptoBackend,
  getNonZeroByteBackend,
  getZeroByteSubtle,
  isFullSupportWebCryptoBackend,
  WebCryptoBackend // eslint-disable-line no-unused-vars
} from '@aws-crypto/web-crypto-backend'

import { bytes2JWK } from './bytes2_jwk'

export interface GetSubtleEncrypt {
  (iv: Uint8Array, additionalData: Uint8Array) : (data: Uint8Array) => Promise<ArrayBuffer>
}

export interface KdfGetSubtleEncrypt {
  (info: Uint8Array) : GetSubtleEncrypt
}

export interface SubtleSign {
  (data: Uint8Array) : PromiseLike<ArrayBuffer>
}

export interface WebCryptoEncryptionMaterialHelper {
  kdfGetSubtleEncrypt: KdfGetSubtleEncrypt
  subtleSign?: SubtleSign
  dispose: () => void
}

export interface GetEncryptHelper {
  (material: WebCryptoEncryptionMaterial) : Promise<WebCryptoEncryptionMaterialHelper>
}

export const getEncryptHelper: GetEncryptHelper = async (material: WebCryptoEncryptionMaterial) => {
  const backend = await getWebCryptoBackend()

  /* Precondition: WebCryptoEncryptionMaterial must have a valid data key. */
  needs(material.hasValidKey(), 'Material has no CryptoKey.')

  const { signatureHash } = material.suite
  const kdfGetSubtleEncrypt = <KdfGetSubtleEncrypt>getSubtleFunction(material, backend, 'encrypt')
  return Object.freeze({
    kdfGetSubtleEncrypt,
    subtleSign: signatureHash ? getSubtleSign : undefined,
    dispose
  })

  function getSubtleSign (data: Uint8Array) {
    if (!signatureHash) throw new Error('Algorithm suite does not support signing.')
    const { signatureKey } = material
    if (!signatureKey) throw new Error('Malformed Material.')
    const { privateKey } = signatureKey
    if (!isCryptoKey(privateKey)) throw new Error('Malformed Material.')
    const algorithm = { name: 'ECDSA', hash: { name: signatureHash } }
    return getNonZeroByteBackend(backend).sign(algorithm, privateKey, data)
  }

  function dispose () {
    material.zeroUnencryptedDataKey()
  }
}

export interface GetSubtleDecrypt extends GetSubtleEncrypt {}

export interface KdfGetSubtleDecrypt {
  (info: Uint8Array) : GetSubtleDecrypt
}

interface SubtleVerify {
  (signature: Uint8Array, data: Uint8Array) : PromiseLike<boolean>
}

export interface WebCryptoDecryptionMaterialHelper {
  kdfGetSubtleDecrypt: KdfGetSubtleDecrypt
  subtleVerify?: SubtleVerify
  dispose: () => void
}

export interface GetDecryptionHelper {
  (material: WebCryptoDecryptionMaterial) : Promise<WebCryptoDecryptionMaterialHelper>
}

export const getDecryptionHelper: GetDecryptionHelper = async (material: WebCryptoDecryptionMaterial) => {
  const backend = await getWebCryptoBackend()

  /* Precondition: WebCryptoDecryptionMaterial must have a valid data key. */
  needs(material.hasValidKey(), 'Material has no valid data key.')

  const { signatureHash } = material.suite

  const kdfGetSubtleDecrypt = <KdfGetSubtleDecrypt>getSubtleFunction(material, backend, 'decrypt')
  return Object.freeze({
    kdfGetSubtleDecrypt,
    subtleVerify: signatureHash ? subtleVerify : undefined,
    dispose
  })

  function subtleVerify (signature: Uint8Array, data: Uint8Array) {
    if (!signatureHash) throw new Error('Algorithm suite does not support signing.')
    const { verificationKey } = material
    if (!verificationKey) throw new Error('Malformed Material.')
    const { publicKey } = verificationKey
    if (!isCryptoKey(publicKey)) throw new Error('Malformed Material.')
    const algorithm = { name: 'ECDSA', hash: { name: signatureHash } }
    return getNonZeroByteBackend(backend).verify(algorithm, publicKey, signature, data)
  }

  function dispose () {
    material.zeroUnencryptedDataKey()
  }
}

type SubtleFunction = 'encrypt'|'decrypt'

export function getSubtleFunction<T extends WebCryptoMaterial<T>> (
  material: T,
  backend: WebCryptoBackend,
  subtleFunction: SubtleFunction = subtleFunctionForMaterial(material)
): KdfGetSubtleEncrypt|KdfGetSubtleDecrypt {
  /* Precondition: The material must have a CryptoKey. */
  needs(material.hasCryptoKey, 'Material must have a CryptoKey.')

  const cryptoKey = material.getCryptoKey()

  /* Precondition: The cryptoKey and backend must match in terms of Mixed vs Full support. */
  needs(isCryptoKey(cryptoKey) === isFullSupportWebCryptoBackend(backend), 'CryptoKey vs WebCrypto backend mismatch.')
  const { suite } = material
  const { encryption: cipherName, ivLength, tagLength } = suite

  return (info: Uint8Array) => {
    const derivedKeyPromise: Promise<AwsEsdkJsCryptoKey|MixedBackendCryptoKey> = isCryptoKey(cryptoKey)
      ? WebCryptoKdf(getNonZeroByteBackend(backend), material, cryptoKey, [subtleFunction], info)
      : Promise.all([
        WebCryptoKdf(getNonZeroByteBackend(backend), material, cryptoKey.nonZeroByteCryptoKey, [subtleFunction], info),
        WebCryptoKdf(getZeroByteSubtle(backend), material, cryptoKey.zeroByteCryptoKey, [subtleFunction], info)
      ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({ nonZeroByteCryptoKey, zeroByteCryptoKey }))
    return (iv: Uint8Array, additionalData: Uint8Array) => {
      /* Precondition: The length of the IV must match the WebCryptoAlgorithmSuite specification. */
      needs(iv.byteLength === ivLength, 'Iv length does not match algorithm suite specification')
      return async (data: Uint8Array) => {
        const deriveKey = await derivedKeyPromise
        if (isCryptoKey(deriveKey) && isFullSupportWebCryptoBackend(backend)) {
          const { subtle } = backend
          const algorithm = { name: cipherName, iv, additionalData, tagLength }
          return subtle[subtleFunction](algorithm, deriveKey, data)
        } else if (!isCryptoKey(deriveKey) && !isFullSupportWebCryptoBackend(backend)) {
          const { nonZeroByteSubtle, zeroByteSubtle } = backend
          const { nonZeroByteCryptoKey, zeroByteCryptoKey } = deriveKey
          const algorithm = { name: cipherName, iv, additionalData, tagLength }
          /* Precondition: The WebCrypto AES-GCM decrypt API expects the data *and* tag together.
           * This means that on decrypt any amount of data less than tagLength is invalid.
           * This also means that zero encrypted data will be equal to tagLength.
           */
          const dataByteLength = subtleFunction === 'decrypt' ? data.byteLength - tagLength / 8 : data.byteLength
          needs(dataByteLength >= 0, 'Invalid data length.')
          if (dataByteLength === 0) {
            return zeroByteSubtle[subtleFunction](algorithm, zeroByteCryptoKey, data)
          } else {
            return nonZeroByteSubtle[subtleFunction](algorithm, nonZeroByteCryptoKey, data)
          }
        }
        // This should be impossible
        throw new Error('Unknown Error')
      }
    }
  }
}

export async function WebCryptoKdf<T extends WebCryptoMaterial<T>> (
  subtle: SubtleCrypto,
  material: T,
  cryptoKey: AwsEsdkJsCryptoKey,
  keyUsages: SubtleFunction[],
  info: Uint8Array
): Promise<CryptoKey> {
  const { kdf, kdfHash, keyLength, encryption } = material.suite

  /* Check for early return (Postcondition): No WebCrypto KDF, just return the unencrypted data key. */
  if (!kdf && !kdfHash) return cryptoKey

  /* Precondition: Valid HKDF values must exist for browsers. */
  needs(
    kdf === 'HKDF' &&
    kdfHash &&
    info instanceof Uint8Array &&
    info.byteLength,
    'Invalid HKDF values.'
  )
  // https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams
  const kdfAlgorithm = { name: kdf, hash: { name: kdfHash }, info, salt: new Uint8Array() }
  const derivedKeyAlgorithm = { name: encryption, length: keyLength }
  const extractable = false
  const deriveKey = await subtle
    .deriveKey(
      // @ts-ignore types need to be updated see: https://developer.mozilla.org/en-US/docs/Web/API/HkdfParams
      kdfAlgorithm,
      cryptoKey,
      derivedKeyAlgorithm,
      extractable,
      keyUsages
    )
  /* Postcondition: The derived key must conform to the algorith suite specification. */
  needs(isValidCryptoKey(deriveKey, material), 'Invalid derived key')
  return deriveKey
}

export async function importCryptoKey<T extends WebCryptoMaterial<T>> (
  backend: WebCryptoBackend,
  material: T,
  keyUsages: KeyUsage[] = [keyUsageForMaterial(material)]
) {
  if (isFullSupportWebCryptoBackend(backend)) {
    return _importCryptoKey(backend.subtle, material, keyUsages)
  } else {
    return Promise.all([
      _importCryptoKey(getNonZeroByteBackend(backend), material, keyUsages),
      _importCryptoKey(getZeroByteSubtle(backend), material, keyUsages)
    ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({ nonZeroByteCryptoKey, zeroByteCryptoKey }))
  }
}

export async function _importCryptoKey<T extends WebCryptoMaterial<T>> (
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
