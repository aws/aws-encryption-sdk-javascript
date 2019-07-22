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
import { getLocalCryptographicMaterialsCache } from '../src/get_local_cryptographic_materials_cache'
import {
  NodeAlgorithmSuite,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  AlgorithmSuiteIdentifier
} from '@aws-crypto/material-management'

const nodeSuite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256)
const encryptionMaterial = new NodeEncryptionMaterial(nodeSuite, {})
const decryptionMaterial = new NodeDecryptionMaterial(nodeSuite, {})

describe('getLocalCryptographicMaterialsCache', () => {
  const {
    getEncryptionResponse,
    getDecryptionResponse,
    del,
    putEncryptionResponse,
    putDecryptionResponse
  } = getLocalCryptographicMaterialsCache(100)

  it('putEncryptionResponse', () => {
    const key = 'some encryption key'
    const response: any = encryptionMaterial

    putEncryptionResponse(key, response, 1)
    const test = getEncryptionResponse(key, 1)
    if (!test) throw new Error('never')
    expect(test.bytesEncrypted).to.equal(2)
    expect(test.messagesEncrypted).to.equal(2)
    expect(test.response === response).to.equal(true)
    expect(Object.isFrozen(test.response)).to.equal(true)
  })

  it('Precondition: putEncryptionResponse plaintextLength can not be negative.', () => {
    const response: any = encryptionMaterial
    const u: any = undefined
    const s: any = 'not-number'
    const n = -1
    expect(() => putEncryptionResponse('key', response, u)).to.throw()
    expect(() => putEncryptionResponse('key', response, s)).to.throw()
    expect(() => putEncryptionResponse('key', response, n)).to.throw()
  })

  it('Postcondition: Only return EncryptionMaterial.', () => {
    const key = 'some decryption key'
    const response: any = decryptionMaterial

    putDecryptionResponse(key, response)
    expect(() => getEncryptionResponse(key, 1)).to.throw()
  })

  it('Precondition: Only cache EncryptionMaterial that is cacheSafe.', () => {
    const key = 'some encryption key'
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const response: any = new NodeEncryptionMaterial(suite, {})

    expect(() => putEncryptionResponse(key, response, 1)).to.throw()
  })

  it('putDecryptionResponse', () => {
    const key = 'some decryption key'
    const response: any = decryptionMaterial

    putDecryptionResponse(key, response)
    const test = getDecryptionResponse(key)
    if (!test) throw new Error('never')
    expect(test.bytesEncrypted).to.equal(0)
    expect(test.messagesEncrypted).to.equal(0)
    expect(test.response === response).to.equal(true)
    expect(Object.isFrozen(test.response)).to.equal(true)
  })

  it('Precondition: Only cache DecryptionMaterial.', () => {
    const key = 'some decryption key'
    const response: any = 'not material'

    expect(() => putDecryptionResponse(key, response)).to.throw()
  })

  it('Precondition: Only cache DecryptionMaterial that is cacheSafe.', () => {
    const key = 'some decryption key'
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const response: any = new NodeEncryptionMaterial(suite, {})

    expect(() => putDecryptionResponse(key, response)).to.throw()
  })

  it('Precondition: plaintextLength can not be negative.', () => {
    const u: any = undefined
    const s: any = 'not-number'
    const n = -1
    expect(() => getEncryptionResponse('key', u)).to.throw()
    expect(() => getEncryptionResponse('key', s)).to.throw()
    expect(() => getEncryptionResponse('key', n)).to.throw()
  })

  it('Check for early return (Postcondition): If this key does not have an EncryptionMaterial, return false.', () => {
    const test = getEncryptionResponse('does-not-exist', 1)
    expect(test).to.equal(false)
  })

  it('Precondition: Only cache EncryptionMaterial.', () => {
    const key = 'some encryption key'
    const response: any = 'not material'

    expect(() => putEncryptionResponse(key, response, 1)).to.throw()
  })

  it('Check for early return (Postcondition): If this key does not have a DecryptionMaterial, return false.', () => {
    const test = getDecryptionResponse('does-not-exist')
    expect(test).to.equal(false)
  })

  it('Postcondition: Only return DecryptionMaterial.', () => {
    const key = 'some encryption key'
    const response: any = encryptionMaterial

    putEncryptionResponse(key, response, 1)
    expect(() => getDecryptionResponse(key))
  })

  it('delete non-existent key', () => {
    del('does-not-exist')
  })

  it('zero is an acceptable plaintextLength', () => {
    const key = 'some encryption key'
    const response: any = encryptionMaterial

    putEncryptionResponse(key, response, 0)
    const test = getEncryptionResponse(key, 0)
    if (!test) throw new Error('never')
    expect(test.bytesEncrypted).to.equal(0)
    expect(test.messagesEncrypted).to.equal(2)
    expect(test.response === response).to.equal(true)
    expect(Object.isFrozen(test.response)).to.equal(true)
  })
})

describe('cache eviction', () => {
  it('putDecryptionResponse can exceed maxSize', () => {
    const {
      getDecryptionResponse,
      putDecryptionResponse
    } = getLocalCryptographicMaterialsCache(1)

    const key1 = 'key lost'
    const key2 = 'key replace'
    const response: any = decryptionMaterial

    putDecryptionResponse(key1, response)
    putDecryptionResponse(key2, response)
    const lost = getDecryptionResponse(key1)
    const found = getDecryptionResponse(key2)
    expect(lost).to.equal(false)
    expect(found).to.not.equal(false)
  })

  it('putDecryptionResponse can be deleted', () => {
    const {
      getDecryptionResponse,
      putDecryptionResponse,
      del
    } = getLocalCryptographicMaterialsCache(1)

    const key = 'key deleted'
    const response: any = decryptionMaterial

    putDecryptionResponse(key, response)
    del(key)
    const lost = getDecryptionResponse(key)
    expect(lost).to.equal(false)
  })

  it('putDecryptionResponse can be garbage collected', async () => {
    const {
      getDecryptionResponse,
      putDecryptionResponse
    } = getLocalCryptographicMaterialsCache(1, 10)

    const key = 'key lost'
    const response: any = decryptionMaterial

    putDecryptionResponse(key, response, 1)
    await new Promise(resolve => setTimeout(resolve, 20))
    const lost = getDecryptionResponse(key)
    expect(lost).to.equal(false)
  })

  it('putEncryptionResponse can exceed maxSize', () => {
    const {
      getEncryptionResponse,
      putEncryptionResponse
    } = getLocalCryptographicMaterialsCache(1)

    const key1 = 'key lost'
    const key2 = 'key replace'
    const response: any = encryptionMaterial

    putEncryptionResponse(key1, response, 0)
    putEncryptionResponse(key2, response, 0)
    const lost = getEncryptionResponse(key1, 0)
    const found = getEncryptionResponse(key2, 0)
    expect(lost).to.equal(false)
    expect(found).to.not.equal(false)
  })

  it('putEncryptionResponse can be deleted', async () => {
    const {
      getEncryptionResponse,
      putEncryptionResponse,
      del
    } = getLocalCryptographicMaterialsCache(1, 10)

    const key = 'key lost'
    const response: any = encryptionMaterial

    putEncryptionResponse(key, response, 1, 1)
    del(key)
    const lost = getEncryptionResponse(key, 1)
    expect(lost).to.equal(false)
  })

  it('putEncryptionResponse can be garbage collected', async () => {
    const {
      getEncryptionResponse,
      putEncryptionResponse
    } = getLocalCryptographicMaterialsCache(1, 10)

    const key = 'key lost'
    const response: any = encryptionMaterial

    putEncryptionResponse(key, response, 1, 1)
    await new Promise(resolve => setTimeout(resolve, 20))
    const lost = getEncryptionResponse(key, 1)
    expect(lost).to.equal(false)
  })
})
