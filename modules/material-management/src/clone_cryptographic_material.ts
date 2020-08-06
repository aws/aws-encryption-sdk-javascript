// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  isEncryptionMaterial,
  isDecryptionMaterial,
} from './cryptographic_material'
import { NodeAlgorithmSuite } from './node_algorithms'
import { AwsEsdkKeyObject } from './types'

type Material =
  | NodeEncryptionMaterial
  | NodeDecryptionMaterial
  | WebCryptoEncryptionMaterial
  | WebCryptoDecryptionMaterial

export function cloneMaterial<M extends Material>(source: M): M {
  const { suite, encryptionContext } = source

  const clone = (suite instanceof NodeAlgorithmSuite
    ? source instanceof NodeEncryptionMaterial
      ? new NodeEncryptionMaterial(suite, encryptionContext)
      : new NodeDecryptionMaterial(suite, encryptionContext)
    : source instanceof WebCryptoEncryptionMaterial
    ? new WebCryptoEncryptionMaterial(suite, encryptionContext)
    : new WebCryptoDecryptionMaterial(suite, encryptionContext)) as M

  if (source.hasUnencryptedDataKey) {
    const udk = cloneUnencryptedDataKey(source.getUnencryptedDataKey())
    clone.setUnencryptedDataKey(udk)
  }

  if ((source as WebCryptoDecryptionMaterial).hasCryptoKey) {
    const cryptoKey = (source as WebCryptoDecryptionMaterial).getCryptoKey()
    ;(clone as WebCryptoDecryptionMaterial).setCryptoKey(cryptoKey)
  }

  if (isEncryptionMaterial(source) && isEncryptionMaterial(clone)) {
    const encryptedDataKeys = source.encryptedDataKeys
    encryptedDataKeys.forEach((edk) => clone.addEncryptedDataKey(edk))

    if (source.suite.signatureCurve && source.signatureKey) {
      clone.setSignatureKey(source.signatureKey)
    }
  } else if (isDecryptionMaterial(source) && isDecryptionMaterial(clone)) {
    if (source.suite.signatureCurve && source.verificationKey) {
      clone.setVerificationKey(source.verificationKey)
    }
  } else {
    throw new Error('Material mismatch')
  }

  return clone
}

function cloneUnencryptedDataKey(dataKey: AwsEsdkKeyObject | Uint8Array) {
  if (dataKey instanceof Uint8Array) {
    return new Uint8Array(dataKey)
  }
  return dataKey
}
