// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringClass,
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
  Newable,
} from '@aws-crypto/material-management-browser'
import { KMS } from 'aws-sdk'
import { version } from './version'
const getKmsClient = getClient(KMS, {
  customUserAgent: `AwsEncryptionSdkJavascriptBrowser/${version}`,
})
const cacheKmsClients = cacheClients(getKmsClient)

export type KmsKeyringWebCryptoInput = Partial<KmsKeyringInput<KMS>>
export type KMSWebCryptoConstructible = KMSConstructible<
  KMS,
  KMS.ClientConfiguration
>
export type KmsWebCryptoClientSupplier = KmsClientSupplier<KMS>

export class KmsKeyringBrowser extends KmsKeyringClass<
  WebCryptoAlgorithmSuite,
  KMS
>(KeyringWebCrypto as Newable<KeyringWebCrypto>) {
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
  getKmsClient,
  limitRegions,
  excludeRegions,
  cacheClients,
  KMS,
}
