// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { cloneMaterial } from '../src/clone_cryptographic_material'
import {
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  NodeAlgorithmSuite,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  unwrapDataKey,
} from '../src/index'

const nodeSuite = new NodeAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
)
const webCryptoSuite = new WebCryptoAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
)
const udk128 = new Uint8Array([
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
])

const edk1 = new EncryptedDataKey({
  providerId: 'keyNamespace',
  providerInfo: 'keyName',
  encryptedDataKey: new Uint8Array([1]),
})
const edk2 = new EncryptedDataKey({
  providerId: 'p2',
  providerInfo: 'pi2',
  encryptedDataKey: new Uint8Array([2]),
})

const cryptoKey: any = {
  type: 'secret',
  algorithm: {
    name: webCryptoSuite.encryption,
    length: webCryptoSuite.keyLength,
  },
  usages: ['encrypt', 'decrypt'],
  extractable: false,
}

describe('cloneMaterial', () => {
  it('clone NodeEncryptionMaterial', () => {
    const material = new NodeEncryptionMaterial(nodeSuite, { some: 'context' })
      .setUnencryptedDataKey(new Uint8Array(udk128))
      .addEncryptedDataKey(edk1)
      .addEncryptedDataKey(edk2)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(NodeEncryptionMaterial)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk128)

    expect(test.encryptedDataKeys).to.deep.equal(material.encryptedDataKeys)
    expect(test.encryptionContext).to.deep.equal(material.encryptionContext)
  })

  it('clone NodeDecryptionMaterial', () => {
    const material = new NodeDecryptionMaterial(nodeSuite, {
      some: 'context',
    }).setUnencryptedDataKey(new Uint8Array(udk128))

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(NodeDecryptionMaterial)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk128)

    expect(test.encryptionContext).to.deep.equal(material.encryptionContext)
  })

  it('clone WebCryptoEncryptionMaterial', () => {
    const material = new WebCryptoEncryptionMaterial(webCryptoSuite, {
      some: 'context',
    })
      .setUnencryptedDataKey(new Uint8Array(udk128))
      .setCryptoKey(cryptoKey)
      .addEncryptedDataKey(edk1)
      .addEncryptedDataKey(edk2)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(WebCryptoEncryptionMaterial)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk128)
    expect(test.getCryptoKey()).to.deep.equal(cryptoKey)

    expect(test.encryptedDataKeys).to.deep.equal(material.encryptedDataKeys)
    expect(test.encryptionContext).to.deep.equal(material.encryptionContext)
  })

  it('clone WebCryptoDecryptionMaterial', () => {
    /* WebCryptoDecryptionMaterial do not have an unencrypted data key. */
    const material = new WebCryptoDecryptionMaterial(webCryptoSuite, {
      some: 'context',
    }).setCryptoKey(cryptoKey)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(WebCryptoDecryptionMaterial)
    expect(test.getCryptoKey()).to.deep.equal(cryptoKey)

    expect(test.encryptionContext).to.deep.equal(material.encryptionContext)
  })
})
