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
import { cloneMaterial } from '../src/clone_cryptographic_material'
import {
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  NodeAlgorithmSuite,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  EncryptedDataKey
} from '@aws-crypto/material-management'

const nodeSuite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
const webCryptoSuite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
const udk128 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
const trace = {
  keyNamespace: 'keyNamespace',
  keyName: 'keyName',
  flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
}

const edk1 = new EncryptedDataKey({ providerId: 'keyNamespace', providerInfo: 'keyName', encryptedDataKey: new Uint8Array([1]) })
const edk2 = new EncryptedDataKey({ providerId: 'p2', providerInfo: 'pi2', encryptedDataKey: new Uint8Array([2]) })

const cryptoKey: any = { type: 'secret', algorithm: { name: webCryptoSuite.encryption, length: webCryptoSuite.keyLength }, usages: ['encrypt', 'decrypt'], extractable: false }

describe('cloneMaterial', () => {
  it('clone NodeEncryptionMaterial', () => {
    const material = new NodeEncryptionMaterial(nodeSuite)
      .setUnencryptedDataKey(udk128, trace)
      .addEncryptedDataKey(edk1, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      .addEncryptedDataKey(edk2, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(NodeEncryptionMaterial)
    expect(test.getUnencryptedDataKey()).to.deep.equal(udk128)
    expect(test.keyringTrace).to.deep.equal(material.keyringTrace)
    expect(test.encryptedDataKeys).to.deep.equal(material.encryptedDataKeys)
  })

  it('clone NodeDecryptionMaterial', () => {
    const material = new NodeDecryptionMaterial(nodeSuite)
      .setUnencryptedDataKey(udk128, trace)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(NodeDecryptionMaterial)
    expect(test.getUnencryptedDataKey()).to.deep.equal(udk128)
    expect(test.keyringTrace).to.deep.equal(material.keyringTrace)
  })

  it('clone WebCryptoEncryptionMaterial', () => {
    const material = new WebCryptoEncryptionMaterial(webCryptoSuite)
      .setUnencryptedDataKey(udk128, trace)
      .setCryptoKey(cryptoKey, trace)
      .addEncryptedDataKey(edk1, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      .addEncryptedDataKey(edk2, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(WebCryptoEncryptionMaterial)
    expect(test.getUnencryptedDataKey()).to.deep.equal(udk128)
    expect(test.getCryptoKey()).to.deep.equal(cryptoKey)
    expect(test.keyringTrace).to.deep.equal(material.keyringTrace)
    expect(test.encryptedDataKeys).to.deep.equal(material.encryptedDataKeys)
  })

  it('clone WebCryptoDecryptionMaterial', () => {
    const material = new WebCryptoDecryptionMaterial(webCryptoSuite)
      .setUnencryptedDataKey(udk128, trace)
      .setCryptoKey(cryptoKey, trace)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(WebCryptoDecryptionMaterial)
    expect(test.getUnencryptedDataKey()).to.deep.equal(udk128)
    expect(test.getCryptoKey()).to.deep.equal(cryptoKey)
    expect(test.keyringTrace).to.deep.equal(material.keyringTrace)
  })
})
