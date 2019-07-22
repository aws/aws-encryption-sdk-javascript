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
import {
  decorateProperties,
  cacheEntryHasExceededLimits,
  getEncryptionMaterials,
  decryptMaterials
} from '../src/caching_cryptographic_materials_decorators'
import { getLocalCryptographicMaterialsCache } from '../src/get_local_cryptographic_materials_cache'
import { buildCryptographicMaterialsCacheKeyHelpers } from '../src/build_cryptographic_materials_cache_key_helpers'
import { createHash } from 'crypto'

import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  EncryptedDataKey,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial
} from '@aws-crypto/material-management'

describe('decorateProperties', () => {
  it('basic usage', () => {
    const test = {} as any
    decorateProperties(test, {
      cache: 'cache' as any,
      backingMaterialsManager: 'backingMaterialsManager' as any,
      maxAge: 10,
      partition: 'something',
      maxBytesEncrypted: 100,
      maxMessagesEncrypted: 200
    } as any)

    expect(test._cache).to.equal('cache')
    expect(test._backingMaterialsManager).to.equal('backingMaterialsManager')

    expect(test._maxAge).to.equal(10)
    expect(test._maxBytesEncrypted).to.equal(100)
    expect(test._maxMessagesEncrypted).to.equal(200)
    expect(test._partition).to.equal('something')
  })

  it('Precondition: A caching material manager needs a cache.', () => {
    const test = {} as any
    const input = {
      backingMaterialsManager: 'backingMaterialsManager' as any,
      maxAge: 10,
      partition: 'something'
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })

  it('Precondition: A caching material manager needs a way to get material.', () => {
    const test = {} as any
    const input = {
      cache: 'cache' as any,
      maxAge: 10,
      partition: 'something'
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })

  it('Precondition: You *can not* cache something forever.', () => {
    const test = {} as any
    const input = {
      cache: 'cache' as any,
      backingMaterialsManager: 'backingMaterialsManager' as any,
      partition: 'something'
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })

  it('Precondition: maxBytesEncrypted must be inside bounds.  i.e. positive and not more than the maximum.', () => {
    const test = {} as any
    const input = {
      cache: 'cache' as any,
      backingMaterialsManager: 'backingMaterialsManager' as any,
      maxAge: 10,
      partition: 'something',
      maxBytesEncrypted: -1
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })

  it('Precondition: maxMessagesEncrypted must be inside bounds.  i.e. positive and not more than the maximum.', () => {
    const test = {} as any
    const input = {
      cache: 'cache' as any,
      backingMaterialsManager: 'backingMaterialsManager' as any,
      maxAge: 10,
      partition: 'something',
      maxMessagesEncrypted: -1
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })

  it('Precondition: partition must be a string.', () => {
    const test = {} as any
    const input = {
      cache: 'cache' as any,
      backingMaterialsManager: 'backingMaterialsManager' as any,
      maxAge: 10
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })
})

describe('cacheEntryHasExceededLimits', () => {
  const test = {} as any
  const maxAge = 10
  const maxBytesEncrypted = 10
  const maxMessagesEncrypted = 10
  decorateProperties(test, {
    cache: 'cache' as any,
    backingMaterialsManager: 'backingMaterialsManager' as any,
    maxAge,
    partition: 'something',
    maxBytesEncrypted,
    maxMessagesEncrypted
  } as any)

  test.cacheEntryHasExceededLimits = cacheEntryHasExceededLimits()

  it('entry has not exceeded limits', () => {
    const entry = {
      now: Date.now(),
      messagesEncrypted: 0,
      bytesEncrypted: 0
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(false)
  })

  it('entry is at the limits', () => {
    const entry = {
      // Time is in the past, so I have to subtract.
      now: Date.now() - maxAge,
      messagesEncrypted: maxBytesEncrypted,
      bytesEncrypted: maxMessagesEncrypted
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(false)
  })

  it('entry exceeds maxAge', () => {
    const entry = {
      // Time is in the past, so I have to subtract.
      now: Date.now() - (maxAge + 1),
      messagesEncrypted: maxBytesEncrypted - 1,
      bytesEncrypted: maxMessagesEncrypted - 1
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(true)
  })

  it('entry exceeds maxBytesEncrypted', () => {
    const entry = {
      // Time is in the past, so I have to subtract.
      now: Date.now() - maxAge,
      messagesEncrypted: maxBytesEncrypted + 1,
      bytesEncrypted: maxMessagesEncrypted
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(true)
  })

  it('entry exceeds maxMessagesEncrypted', () => {
    const entry = {
      // Time is in the past, so I have to subtract.
      now: Date.now() - maxAge,
      messagesEncrypted: maxBytesEncrypted,
      bytesEncrypted: maxMessagesEncrypted + 1
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(true)
  })
})

describe('Cryptographic Material Functions', () => {
  const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256

  const nodeSuite = new NodeAlgorithmSuite(suiteId)
  const udk128 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
  const trace = {
    keyNamespace: 'keyNamespace',
    keyName: 'keyName',
    flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
  }

  const edk1 = new EncryptedDataKey({ providerId: 'keyNamespace', providerInfo: 'keyName', encryptedDataKey: new Uint8Array([1]) })
  const edk2 = new EncryptedDataKey({ providerId: 'p2', providerInfo: 'pi2', encryptedDataKey: new Uint8Array([2]) })

  const encryptionMaterial = new NodeEncryptionMaterial(nodeSuite, {})
    .setUnencryptedDataKey(udk128, trace)
    .addEncryptedDataKey(edk1, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    .addEncryptedDataKey(edk2, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)

  const decryptionMaterial = new NodeDecryptionMaterial(nodeSuite, {})
    .setUnencryptedDataKey(udk128, trace)

  const context = {}

  const _maxAge = 10
  const _maxBytesEncrypted = 10
  const _maxMessagesEncrypted = 10
  const _cache = getLocalCryptographicMaterialsCache(100)
  const _backingMaterialsManager = {
    getEncryptionMaterials () {
      return encryptionMaterial
    },
    decryptMaterials () {
      return decryptionMaterial
    }
  } as any
  const _partition = 'partition'

  const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
  const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString('utf8')
  const sha512 = async (...data: (Uint8Array|string)[]) => data
    .map(item => typeof item === 'string' ? Buffer.from(item, 'hex') : item)
    .reduce((hash, item) => hash.update(item), createHash('sha512'))
    .digest()
  const cacheKeyHelpers = buildCryptographicMaterialsCacheKeyHelpers(fromUtf8, toUtf8, sha512)

  const testCMM = {
    _partition,
    _maxAge,
    _maxBytesEncrypted,
    _maxMessagesEncrypted,
    _cache,
    _backingMaterialsManager,
    _cacheEntryHasExceededLimits: cacheEntryHasExceededLimits(),
    getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
    decryptMaterials: decryptMaterials(cacheKeyHelpers)
  } as any

  describe('getEncryptionMaterials', () => {
    it('basic usage', async () => {
      const test = await testCMM.getEncryptionMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        frameLength: 10,
        plaintextLength: 10
      })
      // The response must be cloned... i.e. not the same.
      expect(test === encryptionMaterial).to.equal(false)
      expect(test.encryptionContext).to.deep.equal(encryptionMaterial.encryptionContext)
      expect(test.getUnencryptedDataKey()).to.deep.equal(encryptionMaterial.getUnencryptedDataKey())
    })
  })

  describe('decryptionMaterial', () => {
    it('basic usage', async () => {
      const test = await testCMM.decryptMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        encryptedDataKeys: [edk1]
      })
      // The response must be cloned... i.e. not the same.
      expect(test === decryptionMaterial).to.equal(false)
      expect(test.encryptionContext).to.deep.equal(decryptionMaterial.encryptionContext)
      expect(test.getUnencryptedDataKey()).to.deep.equal(decryptionMaterial.getUnencryptedDataKey())
    })
  })
})
