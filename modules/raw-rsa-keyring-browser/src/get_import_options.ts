// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  RsaPadding,
  JsonWebKeyRsaAlg,
  RsaHash,
  BinaryKey,
  RsaJsonWebKey,
  RsaImportableKey,
  RsaWrappingKeyAlgorithm,
} from './types'
import {
  MixedBackendCryptoKey,
  needs,
  isCryptoKey,
  AwsEsdkJsCryptoKey,
} from '@aws-crypto/material-management-browser'

type WebCryptoRsaName = keyof typeof JsonWebKeyRsaAlg
const OAEP_SHA1_MFG1: RsaWrappingKeyAlgorithm = {
  name: 'RSA-OAEP',
  hash: { name: 'SHA-1' },
}
Object.freeze(OAEP_SHA1_MFG1)
Object.freeze(OAEP_SHA1_MFG1.hash)

const OAEP_SHA256_MFG1: RsaWrappingKeyAlgorithm = {
  name: 'RSA-OAEP',
  hash: { name: 'SHA-256' },
}
Object.freeze(OAEP_SHA256_MFG1)
Object.freeze(OAEP_SHA256_MFG1.hash)

const OAEP_SHA384_MFG1: RsaWrappingKeyAlgorithm = {
  name: 'RSA-OAEP',
  hash: { name: 'SHA-384' },
}
Object.freeze(OAEP_SHA384_MFG1)
Object.freeze(OAEP_SHA384_MFG1.hash)

const OAEP_SHA512_MFG1: RsaWrappingKeyAlgorithm = {
  name: 'RSA-OAEP',
  hash: { name: 'SHA-512' },
}
Object.freeze(OAEP_SHA512_MFG1)
Object.freeze(OAEP_SHA512_MFG1.hash)

const JsonWebKeyMap: {
  [key in JsonWebKeyRsaAlg]: RsaWrappingKeyAlgorithm
} = Object.freeze({
  [JsonWebKeyRsaAlg['RSA-OAEP']]: OAEP_SHA1_MFG1,
  [JsonWebKeyRsaAlg['RSA-OAEP-256']]: OAEP_SHA256_MFG1,
  [JsonWebKeyRsaAlg['RSA-OAEP-384']]: OAEP_SHA384_MFG1,
  [JsonWebKeyRsaAlg['RSA-OAEP-512']]: OAEP_SHA512_MFG1,
})

const RsaPaddingMap: {
  [key in RsaPadding]: RsaWrappingKeyAlgorithm
} = Object.freeze({
  [RsaPadding.OAEP_SHA1_MFG1]: OAEP_SHA1_MFG1,
  [RsaPadding.OAEP_SHA256_MFG1]: OAEP_SHA256_MFG1,
  [RsaPadding.OAEP_SHA384_MFG1]: OAEP_SHA384_MFG1,
  [RsaPadding.OAEP_SHA512_MFG1]: OAEP_SHA512_MFG1,
})

export function getImportOptions(keyInfo: RsaImportableKey) {
  const { alg } = keyInfo as RsaJsonWebKey
  const { padding } = keyInfo as BinaryKey
  if (JsonWebKeyMap[alg]) {
    return {
      format: 'jwk',
      key: keyInfo as RsaJsonWebKey,
      wrappingAlgorithm: JsonWebKeyMap[alg],
    }
  } else if (RsaPaddingMap[padding]) {
    const { format, key } = keyInfo as BinaryKey
    return {
      format,
      key,
      wrappingAlgorithm: RsaPaddingMap[padding],
    }
  }

  throw new Error('Unsupported RsaImportableKey')
}

export function getWrappingAlgorithm(
  publicKey?: AwsEsdkJsCryptoKey,
  privateKey?: AwsEsdkJsCryptoKey | MixedBackendCryptoKey
) {
  const privateKeys = flattenMixedCryptoKey(privateKey)
  if (publicKey && privateKeys.length) {
    return verify(...[publicKey, ...privateKeys].map(extract))
  } else if (publicKey) {
    return verify(extract(publicKey))
  } else if (privateKeys.length) {
    return verify(...privateKeys.map(extract))
  }
  throw new Error('No Key provided.')
}

export function extract(key: AwsEsdkJsCryptoKey): RsaWrappingKeyAlgorithm {
  const { algorithm } = key
  // @ts-ignore
  const { name, hash } = algorithm
  return { name: name as WebCryptoRsaName, hash }
}

export function verify(...args: RsaWrappingKeyAlgorithm[]) {
  const [wrappingAlgorithm, ...rest] = args
  /* Precondition: Need at least 1 algorithm to verify. */
  needs(wrappingAlgorithm, 'Can not verify an empty set of algorithms.')
  const { name, hash } = wrappingAlgorithm
  /* Precondition: The wrappingAlgorithm name must be a supported value. */
  needs(JsonWebKeyRsaAlg[name], 'Algorithm name is not supported.')
  /* Precondition: The hash name must be a supported value. */
  needs(hash && RsaHash[hash.name], 'Hash name is not supported.')
  /* Check for early return (Postcondition): Only 1 wrappingAlgorithm is clearly valid. */
  if (!rest.length) return wrappingAlgorithm
  /* Precondition: All keys must have the same wrappingAlgorithm. */
  needs(
    rest.every(equalWrappingAlgorithm),
    'Not all RSA keys have the same wrappingAlgorithm.'
  )

  return wrappingAlgorithm

  function equalWrappingAlgorithm(algorithm: RsaWrappingKeyAlgorithm) {
    return (
      algorithm.name === name &&
      algorithm.hash &&
      algorithm.hash.name === hash.name
    )
  }
}

export function flattenMixedCryptoKey(
  key?: AwsEsdkJsCryptoKey | MixedBackendCryptoKey
): AwsEsdkJsCryptoKey[] {
  /* Check for early return (Postcondition): empty inputs should return an empty array. */
  if (!key) return []
  if (isCryptoKey(key)) return [key]
  const { nonZeroByteCryptoKey, zeroByteCryptoKey } = key
  const keys = [nonZeroByteCryptoKey, zeroByteCryptoKey]
  /* Postcondition: Not all keys are CryptoKeys. */
  needs(keys.every(isCryptoKey), 'Not all keys are CryptoKeys.')
  return keys
}
