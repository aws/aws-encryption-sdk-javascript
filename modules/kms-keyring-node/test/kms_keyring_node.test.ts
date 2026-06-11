// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { KmsKeyringNode, getClient } from '../src/index'
import { KMS as V3KMS } from '@aws-sdk/client-kms'
import {
  KeyringNode,
  NodeEncryptionMaterial,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  NodeDecryptionMaterial,
  unwrapDataKey,
} from '@aws-crypto/material-management-node'

describe('KmsKeyringNode::constructor', () => {
  it('constructor decorates', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
    const keyArn =
      'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
    const keyIds = [keyArn]

    const test = new KmsKeyringNode({ generatorKeyId, keyIds })

    expect(test.generatorKeyId).to.equal(generatorKeyId)
    expect(test.keyIds).to.have.lengthOf(1)
    expect(test.keyIds[0]).to.equal(keyArn)
    expect(test.clientProvider).to.be.a('function')
    expect(test.isDiscovery).to.equal(false)
  })

  it('instance of KeyringWebCrypto', () => {
    const test = new KmsKeyringNode({ discovery: true })
    expect(test instanceof KeyringNode).to.equal(true)
  })

  it('forwards discoveryFilter to base KmsKeyring', () => {
    const discoveryFilter = { accountIDs: ['123456789012'], partition: 'aws' }
    const test = new KmsKeyringNode({ discovery: true, discoveryFilter })
    expect(test.isDiscovery).to.equal(true)
    expect(test.discoveryFilter).to.deep.equal(discoveryFilter)
  })

  it('discoveryFilter excludes EDKs from non-allowed accounts on decrypt', async () => {
    const allowedAccount = '111111111111'
    const otherAccount = '222222222222'
    const allowedArn = `arn:aws:kms:us-east-1:${allowedAccount}:key/12345678-1234-1234-1234-123456789012`
    const otherArn = `arn:aws:kms:us-east-1:${otherAccount}:key/12345678-1234-1234-1234-123456789012`

    const decryptCalls: string[] = []
    const clientProvider: any = () => ({
      decrypt: ({ KeyId }: any) => {
        decryptCalls.push(KeyId)
        // Always succeed for the keys the keyring chooses to call.
        return {
          Plaintext: new Uint8Array(16),
          KeyId,
        }
      },
    })

    const keyring = new KmsKeyringNode({
      clientProvider,
      discovery: true,
      discoveryFilter: { accountIDs: [allowedAccount], partition: 'aws' },
    })

    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeDecryptionMaterial(suite, {})
    const edks = [
      new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: otherArn,
        encryptedDataKey: Buffer.from(otherArn),
      }),
      new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: allowedArn,
        encryptedDataKey: Buffer.from(allowedArn),
      }),
    ]

    await keyring.onDecrypt(material, edks)

    // Only the allowed-account EDK should reach KMS.
    expect(decryptCalls).to.deep.equal([allowedArn])
  })

  it('throws when discoveryFilter has empty accountIDs', () => {
    expect(
      () =>
        new KmsKeyringNode({
          discovery: true,
          discoveryFilter: { accountIDs: [], partition: 'aws' },
        })
    ).to.throw('A discovery filter must be able to match something.')
  })

  it('throws when discoveryFilter has empty partition', () => {
    expect(
      () =>
        new KmsKeyringNode({
          discovery: true,
          discoveryFilter: { accountIDs: ['123456789012'], partition: '' },
        })
    ).to.throw('A discovery filter must be able to match something.')
  })

  it('throws when discoveryFilter accountIDs contains an empty string', () => {
    expect(
      () =>
        new KmsKeyringNode({
          discovery: true,
          discoveryFilter: { accountIDs: [''], partition: 'aws' },
        })
    ).to.throw('A discovery filter must be able to match something.')
  })

  it('throws when discoveryFilter is set without discovery=true', () => {
    expect(
      () =>
        new KmsKeyringNode({
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

describe('KmsKeyringNode can encrypt/decrypt with AWS SDK v3 client', () => {
  const generatorKeyId =
    'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
  const keyArn =
    'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
  const keyIds = [keyArn]

  const clientProvider = getClient(V3KMS)

  const keyring = new KmsKeyringNode({ clientProvider, generatorKeyId, keyIds })
  let encryptedDataKey: EncryptedDataKey
  let udk: Uint8Array

  it('can encrypt and create unencrypted data key', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const test = await keyring.onEncrypt(material)
    expect(test.hasValidKey()).to.equal(true)
    udk = unwrapDataKey(test.getUnencryptedDataKey())
    expect(udk).to.have.lengthOf(suite.keyLengthBytes)
    expect(test.encryptedDataKeys).to.have.lengthOf(2)
    const [edk] = test.encryptedDataKeys
    encryptedDataKey = edk
  })

  it('can decrypt an EncryptedDataKey', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new NodeDecryptionMaterial(suite, {})
    const test = await keyring.onDecrypt(material, [encryptedDataKey])
    expect(test.hasValidKey()).to.equal(true)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk)
  })
})
