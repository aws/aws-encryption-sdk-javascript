// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AwsKmsMrkAwareSymmetricKeyringBrowser } from '../src/index'
import {
  KeyringWebCrypto,
  WebCryptoEncryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  WebCryptoDecryptionMaterial,
  KeyringTraceFlag,
} from '@aws-crypto/material-management-browser'
import { KMS as V3KMS } from '@aws-sdk/client-kms'

chai.use(chaiAsPromised)
const { expect } = chai

describe('AwsKmsMrkAwareSymmetricKeyringBrowser::constructor', () => {
  const keyId =
    'arn:aws:kms:us-west-2:658956600833:key/mrk-b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
  const grantTokens = ['grant']
  const client: any = {}
  it('constructor decorates', async () => {
    const test = new AwsKmsMrkAwareSymmetricKeyringBrowser({
      client,
      keyId,
      grantTokens,
    })

    expect(test.keyId).to.equal(keyId)
    expect(test.client).to.equal(client)
    expect(test.grantTokens).to.equal(grantTokens)
  })

  it('instance of KeyringWebCrypto', () => {
    const test = new AwsKmsMrkAwareSymmetricKeyringBrowser({
      client,
      keyId,
      grantTokens,
    })
    expect(test instanceof KeyringWebCrypto).to.equal(true)
  })
})

/* Injected from @aws-sdk/karma-credential-loader. */
declare const credentials: any

describe('AwsKmsMrkAwareSymmetricKeyringBrowser can encrypt/decrypt with AWS SDK v3 client', () => {
  const westKeyId =
    'arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
  const eastKeyId =
    'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
  const grantTokens = ['grant']
  const encryptionContext = { some: 'context' }
  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
  )

  const encryptKeyring = new AwsKmsMrkAwareSymmetricKeyringBrowser({
    client: new V3KMS({ region: 'us-west-2', credentials }),
    keyId: westKeyId,
    grantTokens,
  })
  const decryptKeyring = new AwsKmsMrkAwareSymmetricKeyringBrowser({
    client: new V3KMS({ region: 'us-east-1', credentials }),
    keyId: eastKeyId,
    grantTokens,
  })
  let encryptedDataKey: EncryptedDataKey

  it('can encrypt and create unencrypted data key', async () => {
    const material = new WebCryptoEncryptionMaterial(suite, encryptionContext)
    const test = await encryptKeyring.onEncrypt(material)
    expect(test.hasValidKey()).to.equal(true)
    const udk = test.getUnencryptedDataKey()
    expect(udk).to.have.lengthOf(suite.keyLengthBytes)
    expect(test.encryptedDataKeys).to.have.lengthOf(1)
    const [edk] = test.encryptedDataKeys
    encryptedDataKey = edk
  })

  it('can encrypt a pre-existing plaintext data key', async () => {
    const seedMaterial = new WebCryptoEncryptionMaterial(
      suite,
      encryptionContext
    ).setUnencryptedDataKey(new Uint8Array(suite.keyLengthBytes), {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
    const encryptTest = await encryptKeyring.onEncrypt(seedMaterial)
    expect(encryptTest.hasValidKey()).to.equal(true)
    expect(encryptTest.encryptedDataKeys).to.have.lengthOf(1)
    const [kmsEDK] = encryptTest.encryptedDataKeys
    expect(kmsEDK.providerId).to.equal('aws-kms')
    expect(kmsEDK.providerInfo).to.equal(westKeyId)
  })

  it('can decrypt an EncryptedDataKey', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new WebCryptoDecryptionMaterial(suite, encryptionContext)
    const test = await decryptKeyring.onDecrypt(material, [encryptedDataKey])
    expect(test.hasValidKey()).to.equal(true)
    // The UnencryptedDataKey should be zeroed, because the cryptoKey has been set
    expect(() => test.getUnencryptedDataKey()).to.throw()
  })
})
