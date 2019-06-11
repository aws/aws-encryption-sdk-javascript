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
  importForWebCryptoEncryptionMaterial,
  importForWebCryptoDecryptionMaterial,
  KeyringWebCrypto // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'
import { KMS } from 'aws-sdk' // eslint-disable-line no-unused-vars

const getKmsClient = getClient(KMS)
const cacheKmsClients = cacheClients(getKmsClient)

export type KmsKeyringWebCryptoInput = Partial<KmsKeyringInput<KMS>>
export type KMSWebCryptoConstructible = KMSConstructible<KMS, KMS.ClientConfiguration>
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

    return importForWebCryptoEncryptionMaterial(_material)
  }

  async _onDecrypt (material: WebCryptoDecryptionMaterial, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext) {
    const _material = await super._onDecrypt(material, encryptedDataKeys, context)

    return importForWebCryptoDecryptionMaterial(_material)
  }
}
immutableClass(KmsKeyringBrowser)

export { getClient, cacheKmsClients, limitRegions, excludeRegions, cacheClients, KMS }
