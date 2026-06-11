// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { KmsKeyringBrowser, getClient } from '../src/index'
import { KMS as V3KMS } from '@aws-sdk/client-kms'
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
    const clientProvider = getClient(V3KMS, { credentials })

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

  it('forwards discoveryFilter to base KmsKeyring', () => {
    const discoveryFilter = { accountIDs: ['123456789012'], partition: 'aws' }
    const test = new KmsKeyringBrowser({ discovery: true, discoveryFilter })
    expect(test.isDiscovery).to.equal(true)
    expect(test.discoveryFilter).to.deep.equal(discoveryFilter)
  })

  it('discoveryFilter excludes EDKs from non-allowed accounts on decrypt', async () => {
    const allowedAccount = '111111111111'
    const otherAccount = '222222222222'
    const allowedArn = `arn:aws:kms:us-east-1:${allowedAccount}:key/12345678-1234-1234-1234-123456789012`
    const otherArn = `arn:aws:kms:us-east-1:${otherAccount}:key/12345678-1234-1234-1234-123456789012`

    const decryptCalls: string[] = []
    const mockClientProvider: any = () => ({
      decrypt: ({ KeyId }: any) => {
        decryptCalls.push(KeyId)
        return {
          Plaintext: new Uint8Array(16),
          KeyId,
        }
      },
    })

    const keyring = new KmsKeyringBrowser({
      clientProvider: mockClientProvider,
      discovery: true,
      discoveryFilter: { accountIDs: [allowedAccount], partition: 'aws' },
    })

    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})
    const edks = [
      new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: otherArn,
        encryptedDataKey: new Uint8Array(Buffer.from(otherArn)),
      }),
      new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: allowedArn,
        encryptedDataKey: new Uint8Array(Buffer.from(allowedArn)),
      }),
    ]

    await keyring.onDecrypt(material, edks)

    expect(decryptCalls).to.deep.equal([allowedArn])
  })

  it('throws when discoveryFilter has empty accountIDs', () => {
    expect(
      () =>
        new KmsKeyringBrowser({
          discovery: true,
          discoveryFilter: { accountIDs: [], partition: 'aws' },
        })
    ).to.throw('A discovery filter must be able to match something.')
  })

  it('throws when discoveryFilter has empty partition', () => {
    expect(
      () =>
        new KmsKeyringBrowser({
          discovery: true,
          discoveryFilter: { accountIDs: ['123456789012'], partition: '' },
        })
    ).to.throw('A discovery filter must be able to match something.')
  })

  it('throws when discoveryFilter accountIDs contains an empty string', () => {
    expect(
      () =>
        new KmsKeyringBrowser({
          discovery: true,
          discoveryFilter: { accountIDs: [''], partition: 'aws' },
        })
    ).to.throw('A discovery filter must be able to match something.')
  })

  it('throws when discoveryFilter is set without discovery=true', () => {
    expect(
      () =>
        new KmsKeyringBrowser({
          keyIds: [
            'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
          ],
          discoveryFilter: { accountIDs: ['123456789012'], partition: 'aws' },
        })
    ).to.throw(
      'Account and partition decrypt filtering are only supported when discovery === true'
    )
  })
})

describe('KmsKeyringBrowser can encrypt/decrypt with AWS SDK v3 client', () => {
  const generatorKeyId =
    'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
  const keyArn =
    'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
  const keyIds = [keyArn]
  const clientProvider = getClient(V3KMS, { credentials })
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
