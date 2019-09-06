/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import { KmsKeyringNode } from '../src/index'
import {
  KeyringNode,
  NodeEncryptionMaterial,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey, // eslint-disable-line no-unused-vars
  NodeDecryptionMaterial,
  unwrapDataKey
} from '@aws-crypto/material-management-node'

describe('KmsKeyringNode::constructor', () => {
  it('constructor decorates', async () => {
    const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
    const keyArn = 'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
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
})

describe('RawAesKeyringWebCrypto encrypt/decrypt', () => {
  const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
  const keyArn = 'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
  const keyIds = [keyArn]
  const keyring = new KmsKeyringNode({ generatorKeyId, keyIds })
  let encryptedDataKey: EncryptedDataKey
  let udk: Uint8Array

  it('can encrypt and create unencrypted data key', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256)
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
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256)
    const material = new NodeDecryptionMaterial(suite, {})
    const test = await keyring.onDecrypt(material, [encryptedDataKey])
    expect(test.hasValidKey()).to.equal(true)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk)
  })
})
