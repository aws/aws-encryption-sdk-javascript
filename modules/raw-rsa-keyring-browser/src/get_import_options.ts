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
  RsaPadding,
  JsonWebKeyRsaAlg,
  BinaryKey, // eslint-disable-line no-unused-vars
  RsaJsonWebKey, // eslint-disable-line no-unused-vars
  RsaImportableKey, // eslint-disable-line no-unused-vars
  RsaWrappingKeyAlgorithm // eslint-disable-line no-unused-vars
} from './types'
import {
  MixedBackendCryptoKey, // eslint-disable-line no-unused-vars
  needs,
  isCryptoKey
} from '@aws-crypto/material-management-browser'

type WebCryptoRsaName = 'RSA-OAEP'
const OAEP_SHA1_MFG1: RsaWrappingKeyAlgorithm = { name: 'RSA-OAEP', hash: { name: 'SHA-1' } }
Object.freeze(OAEP_SHA1_MFG1)
Object.freeze(OAEP_SHA1_MFG1.hash)

const OAEP_SHA256_MFG1: RsaWrappingKeyAlgorithm = { name: 'RSA-OAEP', hash: { name: 'SHA-256' } }
Object.freeze(OAEP_SHA256_MFG1)
Object.freeze(OAEP_SHA256_MFG1.hash)

export function getImportOptions (keyInfo: RsaImportableKey) {
  if ((<RsaJsonWebKey>keyInfo).alg === JsonWebKeyRsaAlg['RSA-OAEP']) {
    return {
      format: 'jwk',
      key: (<RsaJsonWebKey>keyInfo),
      wrappingAlgorithm: OAEP_SHA1_MFG1
    }
  } else
  if ((<RsaJsonWebKey>keyInfo).alg === JsonWebKeyRsaAlg['RSA-OAEP-256']) {
    return {
      format: 'jwk',
      key: (<RsaJsonWebKey>keyInfo),
      wrappingAlgorithm: OAEP_SHA256_MFG1
    }
  } else
  if ((<BinaryKey>keyInfo).padding === RsaPadding.OAEP_SHA1_MFG1) {
    const wrappingAlgorithm = OAEP_SHA1_MFG1
    const { format, key } = (<BinaryKey>keyInfo)
    return { format, key, wrappingAlgorithm }
  } else
  if ((<BinaryKey>keyInfo).padding === RsaPadding.OAEP_SHA256_MFG1) {
    const wrappingAlgorithm = OAEP_SHA256_MFG1
    const { format, key } = (<BinaryKey>keyInfo)
    return { format, key, wrappingAlgorithm }
  } else {
    throw new Error('Unsupported RsaImportableKey')
  }
}

export function getWrappingAlgorithm (publicKey?: CryptoKey, privateKey?: CryptoKey|MixedBackendCryptoKey) {
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

export function extract (key: CryptoKey): RsaWrappingKeyAlgorithm {
  const { algorithm } = key
  // @ts-ignore
  const { name, hash } = algorithm
  return { name: (<WebCryptoRsaName>name), hash }
}

export function verify (...args: RsaWrappingKeyAlgorithm[]) {
  const [wrappingAlgorithm, ...rest] = args
  /* Precondition: Need at least 1 algorithm to verify. */
  needs(wrappingAlgorithm, 'Can not verify an empty set of algorithms.')
  const { name, hash } = wrappingAlgorithm
  /* Precondition: The only supported name is 'RSA-OAEP'. */
  needs(name === 'RSA-OAEP', '')
  /* Precondition: The only supported hash names are 'SHA-1'|'SHA-256'. */
  needs(hash && (hash.name === 'SHA-1' || hash.name === 'SHA-256'), '')
  /* Check for early return (Postcondition): Only 1 wrappingAlgorithm is clearly valid. */
  if (!rest.length) return wrappingAlgorithm
  /* Precondition: All keys must have the same wrappingAlgorithm. */
  needs(rest.every(equalWrappingAlgorithm), 'Not all RSA keys have the same wrappingAlgorithm.')

  return wrappingAlgorithm

  function equalWrappingAlgorithm (algorithm: RsaWrappingKeyAlgorithm) {
    return algorithm.name === name &&
      algorithm.hash &&
      algorithm.hash === hash
  }
}

export function flattenMixedCryptoKey (key?: CryptoKey|MixedBackendCryptoKey): CryptoKey[] {
  /* Check for early return (Postcondition): nothing is an empty array. */
  if (!key) return []
  if (isCryptoKey(key)) return [key]
  const { nonZeroByteCryptoKey, zeroByteCryptoKey } = key
  const keys = [nonZeroByteCryptoKey, zeroByteCryptoKey]
  /* Precondition: Not all keys are CryptoKeys. */
  needs(keys.every(isCryptoKey), 'Not all keys are CryptoKeys.')
  return keys
}
