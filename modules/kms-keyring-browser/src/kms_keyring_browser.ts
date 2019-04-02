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
  KmsKeyringClass,
  KeyRingConstructible, // eslint-disable-line no-unused-vars
  KmsKeyringInput, // eslint-disable-line no-unused-vars
  KMSConstructible, // eslint-disable-line no-unused-vars
  KmsClientSupplier, // eslint-disable-line no-unused-vars
  getClient,
  limitRegions,
  excludeRegions,
  cacheClients
} from '@aws-crypto/kms-keyring'
import {
  WebCryptoAlgorithmSuite, // eslint-disable-line no-unused-vars
  WebCryptoEncryptionMaterial, // eslint-disable-line no-unused-vars
  WebCryptoDecryptionMaterial, // eslint-disable-line no-unused-vars
  EncryptionContext, // eslint-disable-line no-unused-vars
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  immutableClass,
  importCryptoKey,
  KeyringWebCrypto // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'
import { getWebCryptoBackend } from '@aws-crypto/web-crypto-backend'
import { KMS, KMSConfiguration } from '@aws-sdk/client-kms-browser' // eslint-disable-line no-unused-vars

const getKmsClient = getClient(KMS)
const cacheKmsClients = cacheClients(getKmsClient)

export type KmsKeyringWebCryptoInput = Partial<KmsKeyringInput<KMS>>
export type KMSWebCryptoConstructible = KMSConstructible<KMS, KMSConfiguration>
export type KmsWebCryptoClientSupplier = KmsClientSupplier<KMS>

export class KmsKeyringBrowser extends KmsKeyringClass(KeyringWebCrypto as KeyRingConstructible<WebCryptoAlgorithmSuite>) {
  constructor ({
    clientProvider = cacheKmsClients,
    keyIds,
    generatorKeyId,
    grantTokens,
    discovery
  }: KmsKeyringWebCryptoInput = {}) {
    super({ clientProvider, keyIds, generatorKeyId, grantTokens, discovery })
  }

  async _onEncrypt (material: WebCryptoEncryptionMaterial, context?: EncryptionContext) {
    const _material = await super._onEncrypt(material, context)

    /* Check for early return (Postcondition): If a cryptoKey has already been imported for encrypt, return. */
    if (_material.hasUnencryptedDataKey && _material.hasCryptoKey) {
      return _material
    }

    const backend = await getWebCryptoBackend()
    const cryptoKey = await importCryptoKey(backend, _material)
    // The trace is only set when the material does not already have
    // an hasUnencryptedDataKey.  This is an implementation detail :(
    const [trace] = _material.keyringTrace

    return _material.setCryptoKey(cryptoKey, trace)
  }

  async _onDecrypt (material: WebCryptoDecryptionMaterial, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext) {
    const _material = await super._onDecrypt(material, encryptedDataKeys, context)

    /* Check for early return (Postcondition): If a cryptoKey has already been imported for decrypt, return. */
    if (_material.hasUnencryptedDataKey && _material.hasCryptoKey) {
      return _material
    }

    const backend = await getWebCryptoBackend()
    const cryptoKey = await importCryptoKey(backend, _material)
    // Now that a cryptoKey has been imported, the unencrypted data key can be zeroed.
    _material.zeroUnencryptedDataKey()
    // The trace is only set when the material does not already have
    // an hasUnencryptedDataKey.  This is an implementation detail :(
    const [trace] = _material.keyringTrace

    return _material.setCryptoKey(cryptoKey, trace)
  }
}
immutableClass(KmsKeyringBrowser)

export { getClient, cacheKmsClients, limitRegions, excludeRegions, cacheClients }
