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
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  isEncryptionMaterial,
  isDecryptionMaterial
} from './cryptographic_material'
import {
  NodeAlgorithmSuite
} from './node_algorithms'
import {
  AwsEsdkKeyObject // eslint-disable-line no-unused-vars
} from './types'
import { KeyringTraceFlag } from './keyring_trace'

type Material = NodeEncryptionMaterial|NodeDecryptionMaterial|WebCryptoEncryptionMaterial|WebCryptoDecryptionMaterial

export function cloneMaterial<M extends Material> (source: M): M {
  const { suite, encryptionContext } = source

  const clone = <M>(suite instanceof NodeAlgorithmSuite
    ? source instanceof NodeEncryptionMaterial
      ? new NodeEncryptionMaterial(suite, encryptionContext)
      : new NodeDecryptionMaterial(suite, encryptionContext)
    : source instanceof WebCryptoEncryptionMaterial
      ? new WebCryptoEncryptionMaterial(suite, encryptionContext)
      : new WebCryptoDecryptionMaterial(suite, encryptionContext))

  /* The WRAPPING_KEY_GENERATED_DATA_KEY _should_ be the first trace,
   * but it is better to look for it explicitly.
   */
  const trace = source.keyringTrace.find(({ flags }) => flags & KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)

  if (source.hasUnencryptedDataKey) {
    const udk = cloneUnencryptedDataKey(source.getUnencryptedDataKey())
    if (!trace) throw new Error('Malformed source material.')
    clone.setUnencryptedDataKey(udk, trace)
  }

  if ((<WebCryptoDecryptionMaterial>source).hasCryptoKey) {
    const cryptoKey = (<WebCryptoDecryptionMaterial>source).getCryptoKey()
    if (!trace) throw new Error('Malformed source material.')
    ;(<WebCryptoDecryptionMaterial>clone)
      .setCryptoKey(cryptoKey, trace)
  }

  if (isEncryptionMaterial(source) && isEncryptionMaterial(clone)) {
    source.encryptedDataKeys.forEach(edk => {
      const { providerInfo, providerId } = edk
      const trace = source.keyringTrace.find(({ keyNamespace, keyName }) => keyName === providerInfo && keyNamespace === providerId)
      if (!trace) throw new Error('Malformed Encrypted Data Key')
      clone.addEncryptedDataKey(edk, trace.flags)
    })

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

function cloneUnencryptedDataKey (dataKey: AwsEsdkKeyObject| Uint8Array) {
  if (dataKey instanceof Uint8Array) {
    return new Uint8Array(dataKey)
  }
  return dataKey
}
