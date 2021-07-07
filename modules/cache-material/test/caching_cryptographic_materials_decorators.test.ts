// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  decorateProperties,
  cacheEntryHasExceededLimits,
  getEncryptionMaterials,
  decryptMaterials,
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
  NodeDecryptionMaterial,
  CommitmentPolicy,
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
      maxMessagesEncrypted: 200,
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
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
      partition: 'something',
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })

  it('Precondition: A caching material manager needs a way to get material.', () => {
    const test = {} as any
    const input = {
      cache: 'cache' as any,
      maxAge: 10,
      partition: 'something',
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })

  it('Precondition: You *can not* cache something forever.', () => {
    const test = {} as any
    const input = {
      cache: 'cache' as any,
      backingMaterialsManager: 'backingMaterialsManager' as any,
      partition: 'something',
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
      maxBytesEncrypted: -1,
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
      maxMessagesEncrypted: -1,
    } as any
    expect(() => decorateProperties(test, input)).to.throw()
  })

  it('Precondition: partition must be a string.', () => {
    const test = {} as any
    const input = {
      cache: 'cache' as any,
      backingMaterialsManager: 'backingMaterialsManager' as any,
      maxAge: 10,
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
    maxMessagesEncrypted,
    commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
  } as any)

  test.cacheEntryHasExceededLimits = cacheEntryHasExceededLimits()

  it('entry has not exceeded limits', () => {
    const entry = {
      now: Date.now(),
      messagesEncrypted: 0,
      bytesEncrypted: 0,
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(false)
  })

  it('entry is at the limits', () => {
    const entry = {
      // Time is in the past, so I have to subtract.
      now: Date.now() - maxAge,
      messagesEncrypted: maxBytesEncrypted,
      bytesEncrypted: maxMessagesEncrypted,
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(false)
  })

  it('entry exceeds maxAge', () => {
    const entry = {
      // Time is in the past, so I have to subtract.
      now: Date.now() - (maxAge + 1),
      messagesEncrypted: maxBytesEncrypted - 1,
      bytesEncrypted: maxMessagesEncrypted - 1,
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(true)
  })

  it('entry exceeds maxBytesEncrypted', () => {
    const entry = {
      // Time is in the past, so I have to subtract.
      now: Date.now() - maxAge,
      messagesEncrypted: maxBytesEncrypted + 1,
      bytesEncrypted: maxMessagesEncrypted,
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(true)
  })

  it('entry exceeds maxMessagesEncrypted', () => {
    const entry = {
      // Time is in the past, so I have to subtract.
      now: Date.now() - maxAge,
      messagesEncrypted: maxBytesEncrypted,
      bytesEncrypted: maxMessagesEncrypted + 1,
    } as any

    expect(test.cacheEntryHasExceededLimits(entry)).to.equal(true)
  })
})

describe('Cryptographic Material Functions', () => {
  const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256

  const nodeSuite = new NodeAlgorithmSuite(suiteId)
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

  const encryptionMaterial = new NodeEncryptionMaterial(nodeSuite, {})
    .setUnencryptedDataKey(udk128, encryptTrace)
    .addEncryptedDataKey(edk1, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    .addEncryptedDataKey(edk2, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)

  const decryptionMaterial = new NodeDecryptionMaterial(
    nodeSuite,
    {}
  ).setUnencryptedDataKey(udk128, decryptTrace)

  const context = {}

  const _maxAge = 10
  const _maxBytesEncrypted = 10
  const _maxMessagesEncrypted = 10
  const _cache = getLocalCryptographicMaterialsCache(100)
  const _backingMaterialsManager = {
    getEncryptionMaterials() {
      return encryptionMaterial
    },
    decryptMaterials() {
      return decryptionMaterial
    },
  } as any
  const _partition = 'partition'

  const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
  const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString('utf8')
  const sha512 = async (...data: (Uint8Array | string)[]) =>
    data
      .map((item) =>
        typeof item === 'string' ? Buffer.from(item, 'hex') : item
      )
      .reduce((hash, item) => hash.update(item), createHash('sha512'))
      .digest()
  const cacheKeyHelpers = buildCryptographicMaterialsCacheKeyHelpers(
    fromUtf8,
    toUtf8,
    sha512
  )

  const testCMM = {
    _partition,
    _maxAge,
    _maxBytesEncrypted,
    _maxMessagesEncrypted,
    _cache,
    _backingMaterialsManager,
    _cacheEntryHasExceededLimits: cacheEntryHasExceededLimits(),
    getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
    decryptMaterials: decryptMaterials(cacheKeyHelpers),
    _commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
  } as any

  describe('getEncryptionMaterials', () => {
    it('basic usage', async () => {
      const test = await testCMM.getEncryptionMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        frameLength: 10,
        plaintextLength: 10,
      })
      // The response must be cloned... i.e. not the same.
      expect(test === encryptionMaterial).to.equal(false)
      expect(test.encryptionContext).to.deep.equal(
        encryptionMaterial.encryptionContext
      )
      expect(test.getUnencryptedDataKey()).to.deep.equal(
        encryptionMaterial.getUnencryptedDataKey()
      )
    })

    it('Check for early return (Postcondition): If I can not cache the EncryptionMaterial, do not even look.', async () => {
      const testCMM = {
        _partition,
        _maxAge,
        _maxBytesEncrypted,
        _maxMessagesEncrypted,
        _cache: {
          getEncryptionMaterial() {
            throw new Error('should not happen')
          },
        },
        _backingMaterialsManager,
        _cacheEntryHasExceededLimits: cacheEntryHasExceededLimits(),
        getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
        decryptMaterials: decryptMaterials(cacheKeyHelpers),
        _commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      } as any

      const testSuiteCacheSafe = await testCMM.getEncryptionMaterials({
        suite: new NodeAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
        ),
        encryptionContext: context,
        frameLength: 10,
        plaintextLength: 10,
      })
      // The response was not cloned... because it did not come from the cache
      expect(testSuiteCacheSafe === encryptionMaterial).to.equal(true)

      const testPlaintext = await testCMM.getEncryptionMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        frameLength: 10,
      })
      // The response was not cloned... because it did not come from the cache
      expect(testPlaintext === encryptionMaterial).to.equal(true)
    })

    it('Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it.', async () => {
      let assertCount = 0
      const testCMM = {
        _partition,
        _maxAge,
        _maxBytesEncrypted,
        _maxMessagesEncrypted,
        _cache: {
          getEncryptionMaterial() {
            assertCount += 1
            return {
              response: encryptionMaterial,
            }
          },
        },
        _backingMaterialsManager,
        _cacheEntryHasExceededLimits: () => {
          assertCount += 1
          return false
        },
        getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
        decryptMaterials: () => {
          throw new Error('this should never happen')
        },
        _commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      } as any

      await testCMM.getEncryptionMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        frameLength: 10,
        plaintextLength: 10,
      })

      expect(assertCount).to.equal(2)
    })

    it('Check for early return (Postcondition): If I can not cache the EncryptionMaterial, just return it.', async () => {
      let assertCount = 0

      const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16

      const nodeSuite = new NodeAlgorithmSuite(suiteId)
      const udk128 = new Uint8Array([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      ])
      const encryptTrace = {
        keyNamespace: 'keyNamespace',
        keyName: 'keyName',
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
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

      const encryptionMaterial = new NodeEncryptionMaterial(nodeSuite, {})
        .setUnencryptedDataKey(udk128, encryptTrace)
        .addEncryptedDataKey(
          edk1,
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
        )
        .addEncryptedDataKey(
          edk2,
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
        )

      const testCMM = {
        _partition,
        _maxAge,
        _maxBytesEncrypted,
        _maxMessagesEncrypted,
        _cache: {
          getEncryptionMaterial() {
            throw new Error('this should never happen')
          },
          del() {},
        },
        _backingMaterialsManager: {
          getEncryptionMaterials() {
            assertCount += 1
            return encryptionMaterial
          },
        },
        _cacheEntryHasExceededLimits: () => {
          throw new Error('this should never happen')
        },
        getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
        decryptMaterials: () => {
          throw new Error('this should never happen')
        },
        _commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      } as any

      const test = await testCMM.getEncryptionMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        frameLength: 10,
        plaintextLength: 10,
      })

      expect(assertCount).to.equal(1)
      expect(test === encryptionMaterial).to.equal(true)
    })

    it('Postcondition: If the material has exceeded limits it MUST NOT be cloned.', async () => {
      let assertCount = 0

      const suiteId =
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256

      const nodeSuite = new NodeAlgorithmSuite(suiteId)
      const udk128 = new Uint8Array([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
      ])
      const encryptTrace = {
        keyNamespace: 'keyNamespace',
        keyName: 'keyName',
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
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

      const encryptionMaterial = new NodeEncryptionMaterial(nodeSuite, {})
        .setUnencryptedDataKey(udk128, encryptTrace)
        .addEncryptedDataKey(
          edk1,
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
        )
        .addEncryptedDataKey(
          edk2,
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
        )

      const testCMM = {
        _partition,
        _maxAge,
        _maxBytesEncrypted,
        _maxMessagesEncrypted,
        _cache: {
          getEncryptionMaterial() {
            assertCount += 1
            return false
          },
          del() {},
        },
        _backingMaterialsManager: {
          getEncryptionMaterials() {
            assertCount += 1
            return encryptionMaterial
          },
        },
        _cacheEntryHasExceededLimits: () => {
          // This is the test.
          // If the entry is cashable,
          // but has exceeded limit...
          assertCount += 1
          return true
        },
        getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
        decryptMaterials: () => {
          throw new Error('this should never happen')
        },
        _commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      } as any

      const test = await testCMM.getEncryptionMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        frameLength: 10,
        plaintextLength: 10,
      })

      expect(assertCount).to.equal(3)
      expect(test === encryptionMaterial).to.equal(true)
    })
  })

  describe('decryptionMaterial', () => {
    it('basic usage', async () => {
      const test = await testCMM.decryptMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        encryptedDataKeys: [edk1],
      })
      // The response must be cloned... i.e. not the same.
      expect(test === decryptionMaterial).to.equal(false)
      expect(test.encryptionContext).to.deep.equal(
        decryptionMaterial.encryptionContext
      )
      expect(test.getUnencryptedDataKey()).to.deep.equal(
        decryptionMaterial.getUnencryptedDataKey()
      )
    })

    it('Check for early return (Postcondition): If I can not cache the DecryptionMaterial, do not even look.', async () => {
      const testCMM = {
        _partition,
        _maxAge,
        _maxBytesEncrypted,
        _maxMessagesEncrypted,
        _cache: {
          getDecryptionMaterial() {
            throw new Error('should not happen')
          },
        },
        _backingMaterialsManager,
        _commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        _cacheEntryHasExceededLimits: cacheEntryHasExceededLimits(),
        getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
        decryptMaterials: decryptMaterials(cacheKeyHelpers),
      } as any

      const testSuiteCacheSafe = await testCMM.decryptMaterials({
        suite: new NodeAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
        ),
        encryptionContext: context,
        encryptedDataKeys: [edk1],
      })
      // The response was not cloned... because it did not come from the cache
      expect(testSuiteCacheSafe === decryptionMaterial).to.equal(true)
    })

    it('Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it.', async () => {
      let assertCount = 0
      const testCMM = {
        _partition,
        _maxAge,
        _maxBytesEncrypted,
        _maxMessagesEncrypted,
        _cache: {
          getDecryptionMaterial() {
            assertCount += 1
            return {
              response: decryptionMaterial,
            }
          },
        },
        _backingMaterialsManager,
        _cacheEntryHasExceededLimits: () => {
          assertCount += 1
          return false
        },
        _commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
        decryptMaterials: decryptMaterials(cacheKeyHelpers),
      } as any

      await testCMM.decryptMaterials({
        suite: nodeSuite,
        encryptionContext: context,
        encryptedDataKeys: [edk1],
      })
      expect(assertCount).to.equal(2)
    })
  })
})
