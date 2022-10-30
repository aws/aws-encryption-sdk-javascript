// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AwsKmsMrkAwareSymmetricKeyringClass,
  AwsKmsMrkAwareSymmetricKeyringInput,
  AwsEsdkKMSInterface,
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

export type AwsKmsMrkAwareSymmetricKeyringWebCryptoInput =
  AwsKmsMrkAwareSymmetricKeyringInput<AwsEsdkKMSInterface>

export class AwsKmsMrkAwareSymmetricKeyringBrowser extends AwsKmsMrkAwareSymmetricKeyringClass<
  WebCryptoAlgorithmSuite,
  AwsEsdkKMSInterface
>(KeyringWebCrypto as Newable<KeyringWebCrypto>) {
  declare client: AwsEsdkKMSInterface
  declare keyId: string
  declare grantTokens?: string[]

  constructor({
    client,
    keyId,
    grantTokens,
  }: AwsKmsMrkAwareSymmetricKeyringWebCryptoInput) {
    super({ client, keyId, grantTokens })
  }

  async _onEncrypt(
    material: WebCryptoEncryptionMaterial
  ): Promise<WebCryptoEncryptionMaterial> {
    const _material = await super._onEncrypt(material)

    return importForWebCryptoEncryptionMaterial(_material)
  }

  async _onDecrypt(
    material: WebCryptoDecryptionMaterial,
    encryptedDataKeys: EncryptedDataKey[]
  ): Promise<WebCryptoDecryptionMaterial> {
    const _material = await super._onDecrypt(material, encryptedDataKeys)

    return importForWebCryptoDecryptionMaterial(_material)
  }
}
immutableClass(AwsKmsMrkAwareSymmetricKeyringBrowser)
