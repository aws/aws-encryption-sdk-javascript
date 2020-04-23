// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { KmsKeyringBrowser, getClient, KMS } from '../src/index'
import {
  KeyringWebCrypto,
  WebCryptoEncryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  WebCryptoDecryptionMaterial,
} from '@aws-crypto/material-management-browser'

chai.use(chaiAsPromised)
const { expect } = chai

/* Injected from @aws-sdk/karma-credential-loader. */
declare const credentials: any

describe('KmsKeyringBrowser::constructor', () => {
  it('constructor decorates', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
    const keyArn =
      'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
    const keyIds = [keyArn]
    const clientProvider = getClient(KMS, { credentials })

    const test = new KmsKeyringBrowser({
      clientProvider,
      generatorKeyId,
      keyIds,
    })

    expect(test.generatorKeyId).to.equal(generatorKeyId)
    expect(test.keyIds).to.have.lengthOf(1)
    expect(test.keyIds[0]).to.equal(keyArn)
    expect(test.clientProvider).to.equal(clientProvider)
    expect(test.isDiscovery).to.equal(false)
  })

  it('instance of KeyringWebCrypto', () => {
    const test = new KmsKeyringBrowser({ discovery: true })
    expect(test instanceof KeyringWebCrypto).to.equal(true)
  })
})

describe('KmsKeyringBrowser encrypt/decrypt', () => {
  const generatorKeyId =
    'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
  const keyArn =
    'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
  const keyIds = [keyArn]
  const clientProvider = getClient(KMS, { credentials })
  const keyring = new KmsKeyringBrowser({
    clientProvider,
    generatorKeyId,
    keyIds,
  })
  let encryptedDataKey: EncryptedDataKey

  it('can encrypt and create unencrypted data key', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoEncryptionMaterial(suite, {})
    const test = await keyring.onEncrypt(material)
    expect(test.hasValidKey()).to.equal(true)
    const udk = test.getUnencryptedDataKey()
    expect(udk).to.have.lengthOf(suite.keyLengthBytes)
    expect(test.encryptedDataKeys).to.have.lengthOf(2)
    const [edk] = test.encryptedDataKeys
    encryptedDataKey = edk
  })

  it('can decrypt an EncryptedDataKey', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const test = await keyring.onDecrypt(material, [encryptedDataKey])
    expect(test.hasValidKey()).to.equal(true)
    // The UnencryptedDataKey should be zeroed, because the cryptoKey has been set
    expect(() => test.getUnencryptedDataKey()).to.throw()
  })
})
