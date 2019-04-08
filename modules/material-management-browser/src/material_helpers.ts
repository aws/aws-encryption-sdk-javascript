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
  WebCryptoMaterial // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'

import {
  getWebCryptoBackend,
  getNonZeroByteBackend,
  getZeroByteSubtle,
  isFullSupportWebCryptoBackend,
  WebCryptoBackend // eslint-disable-line no-unused-vars
} from '@aws-crypto/web-crypto-backend'

import { bytes2JWK } from './bytes2jwk'

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
  needs(material.hasCryptoKey, 'Material must have a CryptoKey.')

  const cryptoKey = material.getCryptoKey()

  /* Precondition: The cryptoKey and backend must match in terms of Mixed vs Full support. */
  needs(isCryptoKey(cryptoKey) !== isFullSupportWebCryptoBackend(backend), 'CryptoKey vs WebCrypto backend mismatch.')
  const { suite } = material
  const { encryption: cipherName, ivLength, tagLength } = suite

  return (info: Uint8Array) => {
    const derivedKeyPromise: Promise<CryptoKey|MixedBackendCryptoKey> = isCryptoKey(cryptoKey)
      ? WebCryptoKdf(getNonZeroByteBackend(backend), material, cryptoKey, [subtleFunction], info)
      : Promise.all([
        WebCryptoKdf(getNonZeroByteBackend(backend), material, cryptoKey.nonZeroByteCryptoKey, [subtleFunction], info),
        WebCryptoKdf(getZeroByteSubtle(backend), material, cryptoKey.zeroByteCryptoKey, [subtleFunction], info)
      ]).then(([nonZeroByteCryptoKey, zeroByteCryptoKey]) => ({ nonZeroByteCryptoKey, zeroByteCryptoKey }))
    return (iv: Uint8Array, additionalData: Uint8Array) => {
      /* Precondition: The length of the IV must match the algorithm suite specification */
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
          if (data.byteLength) {
            return nonZeroByteSubtle[subtleFunction](algorithm, nonZeroByteCryptoKey, data)
          } else {
            return zeroByteSubtle[subtleFunction](algorithm, zeroByteCryptoKey, data)
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
  cryptoKey: CryptoKey,
  keyUsages: SubtleFunction[],
  info: Uint8Array
): Promise<CryptoKey> {
  const { kdf, kdfHash, keyLength, encryption } = material.suite

  if (kdf === 'HKDF' && kdfHash) {
    needs(info && info.byteLength, 'HKDF requires info.')
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
  } else {
    return cryptoKey
  }
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

export function _importCryptoKey<T extends WebCryptoMaterial<T>> (
  subtle: SubtleCrypto,
  material: T,
  keyUsages: KeyUsage[] = [keyUsageForMaterial(material)]
) {
  const jwk = bytes2JWK(material.getUnencryptedDataKey())
  const { suite } = material
  const extractable = false
  const format = 'jwk'
  const algorithm = suite.kdf ? suite.kdf : suite.encryption
  return subtle.importKey(format, jwk, algorithm, extractable, keyUsages)
}
