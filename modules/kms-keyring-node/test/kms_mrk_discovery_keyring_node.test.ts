// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AwsKmsMrkAwareSymmetricDiscoveryKeyringNode } from '../src/index'
import {
  KeyringNode,
  NodeEncryptionMaterial,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  NodeDecryptionMaterial,
  needs,
} from '@aws-crypto/material-management-node'
chai.use(chaiAsPromised)
const { expect } = chai
import { KMS as V3KMS } from '@aws-sdk/client-kms'

describe('AwsKmsMrkAwareSymmetricKeyringNode::constructor', () => {
  it('constructor decorates', async () => {
    const discoveryFilter = { accountIDs: ['658956600833'], partition: 'aws' }
    const grantTokens = ['grant']
    const client: any = { config: { region: 'us-west-2' } }

    const test = new AwsKmsMrkAwareSymmetricDiscoveryKeyringNode({
      client,
      discoveryFilter,
      grantTokens,
    })

    expect(test.discoveryFilter).to.deep.equal(discoveryFilter)
    expect(test.client).to.equal(client)
    expect(test.grantTokens).to.equal(grantTokens)
  })

  it('instance of KeyringNode', () => {
    const discoveryFilter = { accountIDs: ['658956600833'], partition: 'aws' }
    const grantTokens = ['grant']
    const client: any = { config: { region: 'us-west-2' } }

    const test = new AwsKmsMrkAwareSymmetricDiscoveryKeyringNode({
      client,
      discoveryFilter,
      grantTokens,
    })

    expect(test instanceof KeyringNode).to.equal(true)
  })
})

describe('AwsKmsMrkAwareSymmetricDiscoveryKeyringNode can encrypt/decrypt with AWS SDK v3 client', () => {
  const discoveryFilter = { accountIDs: ['658956600833'], partition: 'aws' }
  const keyId =
    'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
  const grantTokens = ['grant']
  const encryptionContext = { some: 'context' }
  const suite = new NodeAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
  )
  const client = new V3KMS({ region: 'us-west-2' })

  const keyring = new AwsKmsMrkAwareSymmetricDiscoveryKeyringNode({
    client,
    discoveryFilter,
    grantTokens,
  })

  it('throws an error on encrypt', async () => {
    const material = new NodeEncryptionMaterial(suite, encryptionContext)
    await expect(keyring.onEncrypt(material)).to.rejectedWith(
      Error,
      'AwsKmsMrkAwareSymmetricDiscoveryKeyring cannot be used to encrypt'
    )
  })

  it('can decrypt an EncryptedDataKey', async () => {
    const { CiphertextBlob } = await client.generateDataKey({
      KeyId: keyId,
      NumberOfBytes: suite.keyLengthBytes,
      EncryptionContext: encryptionContext,
    })
    console.log(CiphertextBlob)
    needs(CiphertextBlob instanceof Uint8Array, 'never')
    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: keyId,
      encryptedDataKey: CiphertextBlob,
    })

    const material = await keyring.onDecrypt(
      new NodeDecryptionMaterial(suite, encryptionContext),
      [edk]
    )
    const decryptTest = await keyring.onDecrypt(material, [edk])
    expect(decryptTest.hasValidKey()).to.equal(true)
  })
})
