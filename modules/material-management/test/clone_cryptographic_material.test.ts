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
  KeyringTraceFlag,
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
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
])
const encryptTrace = {
  keyNamespace: 'keyNamespace',
  keyName: 'keyName',
  flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
}
const decryptTrace = {
  keyNamespace: 'keyNamespace',
  keyName: 'keyName',
  flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
}

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
      .setUnencryptedDataKey(new Uint8Array(udk128), encryptTrace)
      .addEncryptedDataKey(
        edk1,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )
      .addEncryptedDataKey(
        edk2,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(NodeEncryptionMaterial)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk128)
    expect(test.keyringTrace).to.deep.equal(material.keyringTrace)
    expect(test.encryptedDataKeys).to.deep.equal(material.encryptedDataKeys)
    expect(test.encryptionContext).to.deep.equal(material.encryptionContext)
  })

  it('clone NodeDecryptionMaterial', () => {
    const material = new NodeDecryptionMaterial(nodeSuite, {
      some: 'context',
    }).setUnencryptedDataKey(new Uint8Array(udk128), decryptTrace)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(NodeDecryptionMaterial)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk128)
    expect(test.keyringTrace).to.deep.equal(material.keyringTrace)
    expect(test.encryptionContext).to.deep.equal(material.encryptionContext)
  })

  it('clone WebCryptoEncryptionMaterial', () => {
    const material = new WebCryptoEncryptionMaterial(webCryptoSuite, {
      some: 'context',
    })
      .setUnencryptedDataKey(new Uint8Array(udk128), encryptTrace)
      .setCryptoKey(cryptoKey, encryptTrace)
      .addEncryptedDataKey(
        edk1,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )
      .addEncryptedDataKey(
        edk2,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(WebCryptoEncryptionMaterial)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk128)
    expect(test.getCryptoKey()).to.deep.equal(cryptoKey)
    expect(test.keyringTrace).to.deep.equal(material.keyringTrace)
    expect(test.encryptedDataKeys).to.deep.equal(material.encryptedDataKeys)
    expect(test.encryptionContext).to.deep.equal(material.encryptionContext)
  })

  it('clone WebCryptoDecryptionMaterial', () => {
    /* WebCryptoDecryptionMaterial do not have an unencrypted data key. */
    const material = new WebCryptoDecryptionMaterial(webCryptoSuite, {
      some: 'context',
    }).setCryptoKey(cryptoKey, decryptTrace)

    const test = cloneMaterial(material)
    expect(test).to.be.instanceOf(WebCryptoDecryptionMaterial)
    expect(test.getCryptoKey()).to.deep.equal(cryptoKey)
    expect(test.keyringTrace).to.deep.equal(material.keyringTrace)
    expect(test.encryptionContext).to.deep.equal(material.encryptionContext)
  })

  it('Precondition: For each encrypted data key, there must be a trace.', () => {
    const material = new NodeEncryptionMaterial(nodeSuite, { some: 'context' })
      .setUnencryptedDataKey(new Uint8Array(udk128), encryptTrace)
      .addEncryptedDataKey(
        edk1,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )
      .addEncryptedDataKey(
        edk2,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )

    // remove a trace...
    material.keyringTrace.pop()
    expect(() => cloneMaterial(material)).to.throw(
      Error,
      'KeyringTrace length does not match encrypted data keys.'
    )
  })

  it('Precondition: The traces must be in the same order as the encrypted data keys.', () => {
    const material = new NodeEncryptionMaterial(nodeSuite, { some: 'context' })
      .setUnencryptedDataKey(new Uint8Array(udk128), encryptTrace)
      .addEncryptedDataKey(
        edk1,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )
      .addEncryptedDataKey(
        edk2,
        KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
      )

    // @ts-ignore Typescript is trying to save us...
    material.keyringTrace[1].keyName = 'does not exist'
    expect(() => cloneMaterial(material)).to.throw(
      Error,
      'Keyring trace does not match encrypted data key.'
    )
  })

  it('Precondition: On Decrypt there must not be any additional traces other than the setTrace.', () => {
    const material = new NodeDecryptionMaterial(nodeSuite, {
      some: 'context',
    }).setUnencryptedDataKey(new Uint8Array(udk128), decryptTrace)

    // Just push _something_ on
    material.keyringTrace.push({} as any)
    expect(() => cloneMaterial(material)).to.throw(
      Error,
      'Only 1 trace is valid on DecryptionMaterials.'
    )
  })
})
