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
  WebCryptoEncryptionMaterial, // eslint-disable-line no-unused-vars
  WebCryptoDecryptionMaterial, // eslint-disable-line no-unused-vars
  WebCryptoMaterial // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'

import {
  importCryptoKey
} from './material_helpers'

import {
  getWebCryptoBackend
} from '@aws-crypto/web-crypto-backend'

export async function importForWebCryptoEncryptionMaterial (material: WebCryptoEncryptionMaterial) {
  /* Check for early return (Postcondition): If a cryptoKey has already been imported for encrypt, return. */
  if (material.hasUnencryptedDataKey && material.hasCryptoKey) return material

  return importCryptoKeyToMaterial(material)
}

export async function importForWebCryptoDecryptionMaterial (material: WebCryptoDecryptionMaterial) {
  /* Check for early return (Postcondition): If a cryptoKey has already been imported for decrypt, return. */
  if (material.hasValidKey()) return material
  /* Check for early return (Postcondition): If no key was able to be decrypted, return. */
  if (!material.hasUnencryptedDataKey) return material

  return (await importCryptoKeyToMaterial(material))
    /* Now that a cryptoKey has been imported, the unencrypted data key can be zeroed.
     * this is safe, because one and only one EncryptedDataKey should be used to
     * set the unencrypted data key on the material,
     * and in the browser, all crypto operations are done with a CryptoKey
     */
    .zeroUnencryptedDataKey()
}

export async function importCryptoKeyToMaterial<T extends WebCryptoMaterial<T>> (
  material: T
) {
  const backend = await getWebCryptoBackend()
  const cryptoKey = await importCryptoKey(backend, material)
  // The trace is only set when the material does not already have
  // an hasUnencryptedDataKey.  This is an implementation detail :(
  const [trace] = material.keyringTrace

  return material.setCryptoKey(cryptoKey, trace)
}
