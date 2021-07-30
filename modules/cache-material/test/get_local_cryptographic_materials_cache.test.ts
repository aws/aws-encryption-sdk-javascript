// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { getLocalCryptographicMaterialsCache } from '../src/get_local_cryptographic_materials_cache'
import {
  NodeAlgorithmSuite,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  AlgorithmSuiteIdentifier,
} from '@aws-crypto/material-management'

const nodeSuite = new NodeAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
)
const encryptionMaterial = new NodeEncryptionMaterial(nodeSuite, {})
const decryptionMaterial = new NodeDecryptionMaterial(nodeSuite, {})

describe('getLocalCryptographicMaterialsCache', () => {
  const {
    getEncryptionMaterial,
    getDecryptionMaterial,
    del,
    putEncryptionMaterial,
    putDecryptionMaterial,
  } = getLocalCryptographicMaterialsCache(100)

  it('putEncryptionMaterial', () => {
    const key = 'some encryption key'
    const response: any = encryptionMaterial

    putEncryptionMaterial(key, response, 1)
    const test = getEncryptionMaterial(key, 1)
    if (!test) throw new Error('never')
    expect(test.bytesEncrypted).to.equal(2)
    expect(test.messagesEncrypted).to.equal(2)
    expect(test.response === response).to.equal(true)
    expect(Object.isFrozen(test.response)).to.equal(true)
  })

  it('Precondition: putEncryptionMaterial plaintextLength can not be negative.', () => {
    const response: any = encryptionMaterial
    const u: any = undefined
    const s: any = 'not-number'
    const n = -1
    expect(() => putEncryptionMaterial('key', response, u)).to.throw()
    expect(() => putEncryptionMaterial('key', response, s)).to.throw()
    expect(() => putEncryptionMaterial('key', response, n)).to.throw()
  })

  it('Postcondition: Only return EncryptionMaterial.', () => {
    const key = 'some decryption key'
    const response: any = decryptionMaterial

    putDecryptionMaterial(key, response)
    expect(() => getEncryptionMaterial(key, 1)).to.throw()
  })

  it('Precondition: Only cache EncryptionMaterial that is cacheSafe.', () => {
    const key = 'some encryption key'
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const response: any = new NodeEncryptionMaterial(suite, {})

    expect(() => putEncryptionMaterial(key, response, 1)).to.throw()
  })

  it('putDecryptionMaterial', () => {
    const key = 'some decryption key'
    const response: any = decryptionMaterial

    putDecryptionMaterial(key, response)
    const test = getDecryptionMaterial(key)
    if (!test) throw new Error('never')
    expect(test.bytesEncrypted).to.equal(0)
    expect(test.messagesEncrypted).to.equal(0)
    expect(test.response === response).to.equal(true)
    expect(Object.isFrozen(test.response)).to.equal(true)
  })

  it('Precondition: Only cache DecryptionMaterial.', () => {
    const key = 'some decryption key'
    const response: any = 'not material'

    expect(() => putDecryptionMaterial(key, response)).to.throw()
  })

  it('Precondition: Only cache DecryptionMaterial that is cacheSafe.', () => {
    const key = 'some decryption key'
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const response: any = new NodeEncryptionMaterial(suite, {})

    expect(() => putDecryptionMaterial(key, response)).to.throw()
  })

  it('Precondition: plaintextLength can not be negative.', () => {
    const u: any = undefined
    const s: any = 'not-number'
    const n = -1
    expect(() => getEncryptionMaterial('key', u)).to.throw()
    expect(() => getEncryptionMaterial('key', s)).to.throw()
    expect(() => getEncryptionMaterial('key', n)).to.throw()
  })

  it('Check for early return (Postcondition): If this key does not have an EncryptionMaterial, return false.', () => {
    const test = getEncryptionMaterial('does-not-exist', 1)
    expect(test).to.equal(false)
  })

  it('Precondition: Only cache EncryptionMaterial.', () => {
    const key = 'some encryption key'
    const response: any = 'not material'

    expect(() => putEncryptionMaterial(key, response, 1)).to.throw()
  })

  it('Check for early return (Postcondition): If this key does not have a DecryptionMaterial, return false.', () => {
    const test = getDecryptionMaterial('does-not-exist')
    expect(test).to.equal(false)
  })

  it('Postcondition: Only return DecryptionMaterial.', () => {
    const key = 'some encryption key'
    const response: any = encryptionMaterial

    putEncryptionMaterial(key, response, 1)
    expect(() => getDecryptionMaterial(key))
  })

  it('delete non-existent key', () => {
    del('does-not-exist')
  })

  it('zero is an acceptable plaintextLength', () => {
    const key = 'some encryption key'
    const response: any = encryptionMaterial

    putEncryptionMaterial(key, response, 0)
    const test = getEncryptionMaterial(key, 0)
    if (!test) throw new Error('never')
    expect(test.bytesEncrypted).to.equal(0)
    expect(test.messagesEncrypted).to.equal(2)
    expect(test.response === response).to.equal(true)
    expect(Object.isFrozen(test.response)).to.equal(true)
  })
})

describe('cache eviction', () => {
  it('putDecryptionMaterial can exceed capacity', () => {
    const { getDecryptionMaterial, putDecryptionMaterial } =
      getLocalCryptographicMaterialsCache(1)

    const key1 = 'key lost'
    const key2 = 'key replace'
    const response: any = decryptionMaterial

    putDecryptionMaterial(key1, response)
    putDecryptionMaterial(key2, response)
    const lost = getDecryptionMaterial(key1)
    const found = getDecryptionMaterial(key2)
    expect(lost).to.equal(false)
    expect(found).to.not.equal(false)
  })

  it('putDecryptionMaterial can be deleted', () => {
    const { getDecryptionMaterial, putDecryptionMaterial, del } =
      getLocalCryptographicMaterialsCache(1)

    const key = 'key deleted'
    const response: any = decryptionMaterial

    putDecryptionMaterial(key, response)
    del(key)
    const lost = getDecryptionMaterial(key)
    expect(lost).to.equal(false)
  })

  it('putDecryptionMaterial can be garbage collected', async () => {
    const { getDecryptionMaterial, putDecryptionMaterial } =
      getLocalCryptographicMaterialsCache(1, 10)

    const key = 'key lost'
    const response: any = decryptionMaterial

    putDecryptionMaterial(key, response, 1)
    await new Promise((resolve) => setTimeout(resolve, 20))
    const lost = getDecryptionMaterial(key)
    expect(lost).to.equal(false)
  })

  it('putEncryptionMaterial can exceed capacity', () => {
    const { getEncryptionMaterial, putEncryptionMaterial } =
      getLocalCryptographicMaterialsCache(1)

    const key1 = 'key lost'
    const key2 = 'key replace'
    const response: any = encryptionMaterial

    putEncryptionMaterial(key1, response, 0)
    putEncryptionMaterial(key2, response, 0)
    const lost = getEncryptionMaterial(key1, 0)
    const found = getEncryptionMaterial(key2, 0)
    expect(lost).to.equal(false)
    expect(found).to.not.equal(false)
  })

  it('putEncryptionMaterial can be deleted', async () => {
    const { getEncryptionMaterial, putEncryptionMaterial, del } =
      getLocalCryptographicMaterialsCache(1, 10)

    const key = 'key lost'
    const response: any = encryptionMaterial

    putEncryptionMaterial(key, response, 1, 1)
    del(key)
    const lost = getEncryptionMaterial(key, 1)
    expect(lost).to.equal(false)
  })

  it('putEncryptionMaterial can be garbage collected', async () => {
    const { getEncryptionMaterial, putEncryptionMaterial } =
      getLocalCryptographicMaterialsCache(1, 10)

    const key = 'key lost'
    const response: any = encryptionMaterial

    putEncryptionMaterial(key, response, 1, 1)
    await new Promise((resolve) => setTimeout(resolve, 20))
    const lost = getEncryptionMaterial(key, 1)
    expect(lost).to.equal(false)
  })
})
