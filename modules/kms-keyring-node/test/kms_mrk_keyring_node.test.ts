// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AwsKmsMrkAwareSymmetricKeyringNode } from '../src/index'
import {
  KeyringNode,
  NodeEncryptionMaterial,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  NodeDecryptionMaterial,
  unwrapDataKey,
  KeyringTraceFlag,
} from '@aws-crypto/material-management-node'
import { KMS as V3KMS } from '@aws-sdk/client-kms'

chai.use(chaiAsPromised)
const { expect } = chai

describe('AwsKmsMrkAwareSymmetricKeyringNode::constructor', () => {
  it('constructor decorates', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
    const grantTokens = ['grant']
    const client: any = {}

    const test = new AwsKmsMrkAwareSymmetricKeyringNode({
      client,
      keyId,
      grantTokens,
    })

    expect(test.keyId).to.equal(keyId)
    expect(test.client).to.equal(client)
    expect(test.grantTokens).to.equal(grantTokens)
  })

  it('instance of KeyringNode', () => {
    const keyId =
      'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
    const grantTokens = ['grant']
    const client: any = {}

    const test = new AwsKmsMrkAwareSymmetricKeyringNode({
      client,
      keyId,
      grantTokens,
    })

    expect(test instanceof KeyringNode).to.equal(true)
  })
})

describe('AwsKmsMrkAwareSymmetricKeyringNode can encrypt/decrypt with AWS SDK v3 client', () => {
  const westKeyId =
    'arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
  const eastKeyId =
    'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
  const grantTokens = ['grant']
  const encryptionContext = { some: 'context' }
  const suite = new NodeAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
  )

  const encryptKeyring = new AwsKmsMrkAwareSymmetricKeyringNode({
    client: new V3KMS({ region: 'us-west-2' }),
    keyId: westKeyId,
    grantTokens,
  })

  const decryptKeyring = new AwsKmsMrkAwareSymmetricKeyringNode({
    client: new V3KMS({ region: 'us-east-1' }),
    keyId: eastKeyId,
    grantTokens,
  })
  let encryptedDataKey: EncryptedDataKey
  let udk: Uint8Array

  it('can encrypt and create unencrypted data key', async () => {
    const material = new NodeEncryptionMaterial(suite, encryptionContext)
    const encryptTest = await encryptKeyring.onEncrypt(material)
    expect(encryptTest.hasValidKey()).to.equal(true)
    udk = unwrapDataKey(encryptTest.getUnencryptedDataKey())
    expect(udk).to.have.lengthOf(suite.keyLengthBytes)
    expect(encryptTest.encryptedDataKeys).to.have.lengthOf(1)
    const [edk] = encryptTest.encryptedDataKeys
    encryptedDataKey = edk
  })

  it('can encrypt a pre-existing plaintext data key', async () => {
    const seedMaterial = new NodeEncryptionMaterial(
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
    const material = new NodeDecryptionMaterial(suite, encryptionContext)
    const decryptTest = await decryptKeyring.onDecrypt(material, [
      encryptedDataKey,
    ])
    expect(decryptTest.hasValidKey()).to.equal(true)
    expect(unwrapDataKey(decryptTest.getUnencryptedDataKey())).to.deep.equal(
      udk
    )
  })
})
