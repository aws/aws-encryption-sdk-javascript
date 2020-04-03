// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  immutableClass,
  importForWebCryptoEncryptionMaterial,
  importForWebCryptoDecryptionMaterial,
  KeyringWebCrypto // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'
import { KMS } from 'aws-sdk' // eslint-disable-line no-unused-vars

const getKmsClient = getClient(KMS, { customUserAgent: 'AwsEncryptionSdkJavascriptBrowser' })
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

  async _onEncrypt (material: WebCryptoEncryptionMaterial) {
    const _material = await super._onEncrypt(material)

    return importForWebCryptoEncryptionMaterial(_material)
  }

  async _onDecrypt (material: WebCryptoDecryptionMaterial, encryptedDataKeys: EncryptedDataKey[]) {
    const _material = await super._onDecrypt(material, encryptedDataKeys)

    return importForWebCryptoDecryptionMaterial(_material)
  }
}
immutableClass(KmsKeyringBrowser)

export { getClient, cacheKmsClients, limitRegions, excludeRegions, cacheClients, KMS }
