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
import { needs } from './needs'

type Material =
  | NodeEncryptionMaterial
  | NodeDecryptionMaterial
  | WebCryptoEncryptionMaterial
  | WebCryptoDecryptionMaterial

export function cloneMaterial<M extends Material>(source: M): M {
  const { suite, encryptionContext } = source

  const clone = (
    suite instanceof NodeAlgorithmSuite
      ? source instanceof NodeEncryptionMaterial
        ? new NodeEncryptionMaterial(suite, encryptionContext)
        : new NodeDecryptionMaterial(suite, encryptionContext)
      : source instanceof WebCryptoEncryptionMaterial
      ? new WebCryptoEncryptionMaterial(suite, encryptionContext)
      : new WebCryptoDecryptionMaterial(suite, encryptionContext)
  ) as M

  /* The setTrace _must_ be the first trace,
   * If the material is an EncryptionMaterial
   * then the data key *must* have been generated.
   * If the material is DecryptionMaterial
   * then the data key *must* have been decrypted.
   * i.e. the required flags are:
   * WRAPPING_KEY_GENERATED_DATA_KEY, WRAPPING_KEY_DECRYPTED_DATA_KEY
   * These are controlled by the material itself.
   * Furthermore, subsequent trace entries,
   * *must* be in the same order as the added encrypted data keys.
   * See cryptographic_materials.ts `decorateCryptographicMaterial`, `decorateWebCryptoMaterial`.
   */
  const [setTrace, ...traces] = source.keyringTrace.slice()

  if (source.hasUnencryptedDataKey) {
    const udk = cloneUnencryptedDataKey(source.getUnencryptedDataKey())
    clone.setUnencryptedDataKey(udk, setTrace)
  }

  if ((source as WebCryptoDecryptionMaterial).hasCryptoKey) {
    const cryptoKey = (source as WebCryptoDecryptionMaterial).getCryptoKey()
    ;(clone as WebCryptoDecryptionMaterial).setCryptoKey(cryptoKey, setTrace)
  }

  if (isEncryptionMaterial(source) && isEncryptionMaterial(clone)) {
    const encryptedDataKeys = source.encryptedDataKeys
    /* Precondition: For each encrypted data key, there must be a trace. */
    needs(
      encryptedDataKeys.length === traces.length,
      'KeyringTrace length does not match encrypted data keys.'
    )
    encryptedDataKeys.forEach((edk, i) => {
      const { providerInfo, providerId } = edk
      const { keyNamespace, keyName, flags } = traces[i]
      /* Precondition: The traces must be in the same order as the encrypted data keys. */
      needs(
        keyName === providerInfo && keyNamespace === providerId,
        'Keyring trace does not match encrypted data key.'
      )
      clone.addEncryptedDataKey(edk, flags)
    })

    if (source.suite.signatureCurve && source.signatureKey) {
      clone.setSignatureKey(source.signatureKey)
    }
  } else if (isDecryptionMaterial(source) && isDecryptionMaterial(clone)) {
    /* Precondition: On Decrypt there must not be any additional traces other than the setTrace. */
    needs(!traces.length, 'Only 1 trace is valid on DecryptionMaterials.')
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
