// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringClass,
  KeyRingConstructible,
  KmsKeyringInput,
  KMSConstructible,
  KmsClientSupplier,
  getClient,
  limitRegions,
  excludeRegions,
  cacheClients,
} from '@aws-crypto/kms-keyring'
import {
  WebCryptoAlgorithmSuite,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  EncryptedDataKey,
  immutableClass,
  importForWebCryptoEncryptionMaterial,
  importForWebCryptoDecryptionMaterial,
  KeyringWebCrypto,
} from '@aws-crypto/material-management-browser'
import { KMS } from 'aws-sdk'

const getKmsClient = getClient(KMS, {
  customUserAgent: 'AwsEncryptionSdkJavascriptBrowser',
})
const cacheKmsClients = cacheClients(getKmsClient)

export type KmsKeyringWebCryptoInput = Partial<KmsKeyringInput<KMS>>
export type KMSWebCryptoConstructible = KMSConstructible<
  KMS,
  KMS.ClientConfiguration
>
export type KmsWebCryptoClientSupplier = KmsClientSupplier<KMS>

export class KmsKeyringBrowser extends KmsKeyringClass(
  KeyringWebCrypto as KeyRingConstructible<WebCryptoAlgorithmSuite>
) {
  constructor({
    clientProvider = cacheKmsClients,
    keyIds,
    generatorKeyId,
    grantTokens,
    discovery,
  }: KmsKeyringWebCryptoInput = {}) {
    super({ clientProvider, keyIds, generatorKeyId, grantTokens, discovery })
  }

  async _onEncrypt(material: WebCryptoEncryptionMaterial) {
    const _material = await super._onEncrypt(material)

    return importForWebCryptoEncryptionMaterial(_material)
  }

  async _onDecrypt(
    material: WebCryptoDecryptionMaterial,
    encryptedDataKeys: EncryptedDataKey[]
  ) {
    const _material = await super._onDecrypt(material, encryptedDataKeys)

    return importForWebCryptoDecryptionMaterial(_material)
  }
}
immutableClass(KmsKeyringBrowser)

export {
  getClient,
  cacheKmsClients,
  limitRegions,
  excludeRegions,
  cacheClients,
  KMS,
}
