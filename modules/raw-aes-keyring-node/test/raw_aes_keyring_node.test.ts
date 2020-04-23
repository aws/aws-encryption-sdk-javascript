// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { RawAesKeyringNode, RawAesWrappingSuiteIdentifier } from '../src/index'
import {
  NodeEncryptionMaterial,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  EncryptedDataKey,
  NodeDecryptionMaterial,
  unwrapDataKey,
} from '@aws-crypto/material-management-node'

chai.use(chaiAsPromised)
const { expect } = chai

describe('RawAesKeyringNode::constructor', () => {
  const wrappingSuite =
    RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const unencryptedMasterKey = new Uint8Array(128 / 8)
  const keyNamespace = 'keyNamespace'
  const keyName = 'keyName'

  it('constructor decorates', async () => {
    const test = new RawAesKeyringNode({
      keyName,
      keyNamespace,
      unencryptedMasterKey,
      wrappingSuite,
    })
    expect(test.keyName).to.equal(keyName)
    expect(test.keyNamespace).to.equal(keyNamespace)
    expect(test._wrapKey).to.be.a('function')
    expect(test._unwrapKey).to.be.a('function')
  })

  it('Precondition: AesKeyringNode needs identifying information for encrypt and decrypt.', async () => {
    expect(
      () =>
        new RawAesKeyringNode({
          keyNamespace,
          unencryptedMasterKey,
          wrappingSuite,
        } as any)
    ).to.throw()
    expect(
      () =>
        new RawAesKeyringNode({
          keyName,
          unencryptedMasterKey,
          wrappingSuite,
        } as any)
    ).to.throw()
  })

  it('Precondition: RawAesKeyringNode requires wrappingSuite to be a valid RawAesWrappingSuite.', async () => {
    expect(
      () =>
        new RawAesKeyringNode({
          keyName,
          keyNamespace,
          unencryptedMasterKey,
          wrappingSuite: 111 as any,
        })
    ).to.throw()
  })

  it('Precondition: unencryptedMasterKey must correspond to the NodeAlgorithmSuite specification.', async () => {
    expect(
      () =>
        new RawAesKeyringNode({
          keyName,
          keyNamespace,
          unencryptedMasterKey,
          wrappingSuite:
            RawAesWrappingSuiteIdentifier.AES192_GCM_IV12_TAG16_NO_PADDING,
        })
    ).to.throw()
  })
})

describe('RawAesKeyringNode::_filter', () => {
  const wrappingSuite =
    RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const unencryptedMasterKey = new Uint8Array(128 / 8)
  const keyNamespace = 'keyNamespace'
  const keyName = 'keyName'
  const keyring = new RawAesKeyringNode({
    keyName,
    keyNamespace,
    unencryptedMasterKey,
    wrappingSuite,
  })

  it('true', async () => {
    const test = keyring._filter({
      providerId: keyNamespace,
      providerInfo: keyName,
    } as any)
    expect(test).to.equal(true)
  })

  it('true', async () => {
    const test = keyring._filter({
      providerId: keyNamespace,
      providerInfo: keyName + 'other stuff',
    } as any)
    expect(test).to.equal(true)
  })

  it('false', async () => {
    expect(
      keyring._filter({
        providerId: 'not: keyNamespace',
        providerInfo: keyName + 'other stuff',
      } as any)
    ).to.equal(false)

    expect(
      keyring._filter({
        providerId: keyNamespace,
        providerInfo: 'not: keyName',
      } as any)
    ).to.equal(false)
  })
})

describe('RawAesKeyringNode encrypt/decrypt', () => {
  const wrappingSuite =
    RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const unencryptedMasterKey = new Uint8Array(128 / 8)
  const keyNamespace = 'keyNamespace'
  const keyName = 'keyName'
  const keyring = new RawAesKeyringNode({
    keyName,
    keyNamespace,
    unencryptedMasterKey,
    wrappingSuite,
  })
  let encryptedDataKey: EncryptedDataKey

  it('can encrypt and create unencrypted data key', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new NodeEncryptionMaterial(suite, {})
    const test = await keyring.onEncrypt(material)
    expect(test.hasValidKey()).to.equal(true)
    const udk = unwrapDataKey(test.getUnencryptedDataKey())
    expect(udk).to.have.lengthOf(suite.keyLengthBytes)
    expect(test.encryptedDataKeys).to.have.lengthOf(1)
    const [edk] = test.encryptedDataKeys
    expect(edk.providerId).to.equal(keyNamespace)
    encryptedDataKey = edk
  })

  it('can decrypt an EncryptedDataKey', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const material = new NodeDecryptionMaterial(suite, {})
    const test = await keyring.onDecrypt(material, [encryptedDataKey])
    expect(test.hasValidKey()).to.equal(true)
  })
})
