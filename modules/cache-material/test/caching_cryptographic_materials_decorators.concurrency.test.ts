// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  cacheEntryHasExceededLimits,
  getEncryptionMaterials,
  decryptMaterials,
} from '../src/caching_cryptographic_materials_decorators'
import { SHARED_REQUESTS, batchesByCache } from '../src/shared_requests'
import * as cacheMaterial from '../src/index'
import { getLocalCryptographicMaterialsCache } from '../src/get_local_cryptographic_materials_cache'
import { buildCryptographicMaterialsCacheKeyHelpers } from '../src/build_cryptographic_materials_cache_key_helpers'
import { createHash, randomBytes } from 'crypto'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  EncryptedDataKey,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  unwrapDataKey,
} from '@aws-crypto/material-management'

const suite = new NodeAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
)
const uncacheableSuite = new NodeAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
)
const edk = new EncryptedDataKey({
  providerId: 'keyNamespace',
  providerInfo: 'keyName',
  encryptedDataKey: new Uint8Array([1]),
})
const trace = { keyNamespace: 'keyNamespace', keyName: 'keyName' }

const cacheKeyHelpers = buildCryptographicMaterialsCacheKeyHelpers(
  (input: string) => Buffer.from(input, 'utf8'),
  (input: Uint8Array) => Buffer.from(input).toString('utf8'),
  async (...data: (Uint8Array | string)[]) =>
    data
      .map((item) =>
        typeof item === 'string' ? Buffer.from(item, 'hex') : item
      )
      .reduce((hash, item) => hash.update(item), createHash('sha512'))
      .digest()
)

// Shortened timings, so the tests run in milliseconds.
const FAST = { graceInterval: 20, inFlightTTL: 100 }
const DEFAULT = { ...SHARED_REQUESTS }

// A backing materials manager that takes 5 ms per request and returns a new data key each time.
// `outcomes` decides each call in order: 'ok', 'fail', or 'hang'; later calls use the last one.
function slowBackingMaterialsManager({
  outcomes = ['ok'] as ('ok' | 'fail' | 'hang')[],
  materialSuite = suite,
} = {}) {
  const calls = { encrypt: 0, decrypt: 0, active: 0, peak: 0 }
  let n = 0
  const respond = async () => {
    const outcome = outcomes[Math.min(n++, outcomes.length - 1)]
    if (outcome === 'hang') await new Promise<never>(() => undefined)
    calls.active += 1
    calls.peak = Math.max(calls.peak, calls.active)
    await new Promise((resolve) => setTimeout(resolve, 5))
    calls.active -= 1
    if (outcome === 'fail')
      throw new Error('backing materials manager unavailable')
  }
  return {
    calls,
    async getEncryptionMaterials() {
      calls.encrypt += 1
      await respond()
      return new NodeEncryptionMaterial(materialSuite, {})
        .setUnencryptedDataKey(randomBytes(16), {
          ...trace,
          flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
        })
        .addEncryptedDataKey(
          edk,
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
        )
    },
    async decryptMaterials() {
      calls.decrypt += 1
      await respond()
      return new NodeDecryptionMaterial(suite, {}).setUnencryptedDataKey(
        randomBytes(16),
        { ...trace, flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
      )
    },
  }
}

function cachingCMM(
  backing: any,
  {
    maxMessagesEncrypted = 1000,
    maxBytesEncrypted = 1000,
    cache = getLocalCryptographicMaterialsCache(100),
  } = {}
) {
  return {
    _partition: 'partition',
    _maxAge: 1000 * 60,
    _maxBytesEncrypted: maxBytesEncrypted,
    _maxMessagesEncrypted: maxMessagesEncrypted,
    _cache: cache,
    _backingMaterialsManager: backing,
    _cacheEntryHasExceededLimits: cacheEntryHasExceededLimits(),
    getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
    decryptMaterials: decryptMaterials(cacheKeyHelpers),
  } as any
}

const encryptRequest = { suite, encryptionContext: {}, plaintextLength: 1 }
const decryptRequest = {
  suite,
  encryptionContext: {},
  encryptedDataKeys: [edk],
}

function startEncrypts(cmm: any, lengths: number[], request: any = {}) {
  return lengths.map(async (plaintextLength) =>
    cmm.getEncryptionMaterials({
      ...encryptRequest,
      ...request,
      plaintextLength,
    })
  )
}

async function encryptConcurrently(cmm: any, lengths: number[], request?: any) {
  return Promise.all(startEncrypts(cmm, lengths, request))
}

const times = (count: number, length = 1) =>
  Array.from({ length: count }, () => length)

// Messages and bytes encrypted under each distinct data key.
function usageByDataKey(materials: any[], lengths: number[]) {
  const usage = new Map<string, { messages: number; bytes: number }>()
  materials.forEach((material, i) => {
    const dataKey = Buffer.from(
      unwrapDataKey(material.getUnencryptedDataKey())
    ).toString('hex')
    const entry = usage.get(dataKey) || { messages: 0, bytes: 0 }
    entry.messages += 1
    entry.bytes += lengths[i]
    usage.set(dataKey, entry)
  })
  return [...usage.values()]
}

describe('caching materials manager: concurrent cache misses (#1665)', () => {
  beforeEach(() => Object.assign(SHARED_REQUESTS, FAST))
  afterEach(() => Object.assign(SHARED_REQUESTS, DEFAULT))

  it('concurrent encrypts share data keys without exceeding maxMessagesEncrypted', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing, { maxMessagesEncrypted: 5 })

    const materials = await encryptConcurrently(cmm, times(10))

    expect(backing.calls.encrypt).to.equal(2)
    expect(backing.calls.peak).to.equal(2)
    expect(
      usageByDataKey(materials, times(10)).map((u) => u.messages)
    ).to.deep.equal([5, 5])
  })

  it('concurrent encrypts share data keys without exceeding maxBytesEncrypted', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing, { maxBytesEncrypted: 10 })

    const materials = await encryptConcurrently(cmm, times(10, 3))

    expect(backing.calls.encrypt).to.equal(4)
    expect(
      usageByDataKey(materials, times(10, 3)).map((u) => u.bytes)
    ).to.deep.equal([9, 9, 9, 3])
  })

  it('a large burst runs its backing requests in parallel', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing, { maxMessagesEncrypted: 5 })

    const materials = await encryptConcurrently(cmm, times(100))

    expect(backing.calls.encrypt).to.equal(20)
    expect(backing.calls.peak).to.equal(20)
    for (const { messages } of usageByDataKey(materials, times(100))) {
      expect(messages).to.be.at.most(5)
    }
  })

  it('a warm entry serves callers until its limit, then one request serves the rest', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing, { maxMessagesEncrypted: 5 })
    const warm = await cmm.getEncryptionMaterials(encryptRequest)

    const materials = await encryptConcurrently(cmm, times(10))

    expect(backing.calls.encrypt).to.equal(3)
    for (const { messages } of usageByDataKey(
      [warm, ...materials],
      times(11)
    )) {
      expect(messages).to.be.at.most(5)
    }
  })

  it('keeps every data key within its limits for mixed plaintext sizes', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing, {
      maxBytesEncrypted: 10,
      maxMessagesEncrypted: 3,
    })
    const lengths = [6, 3, 1, 11, 4, 4, 2, 11, 9, 1, 1, 5]

    const materials = await encryptConcurrently(cmm, lengths)

    for (const { messages, bytes } of usageByDataKey(materials, lengths)) {
      expect(messages).to.be.at.most(3)
      if (messages > 1) expect(bytes).to.be.at.most(10)
    }
  })

  it('concurrent decrypts share one backing request', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing)

    await Promise.all(
      Array.from({ length: 10 }, async () =>
        cmm.decryptMaterials(decryptRequest)
      )
    )

    expect(backing.calls.decrypt).to.equal(1)
  })

  it('serves every waiting caller even when the cache evicts the entry at once', async () => {
    const backing = slowBackingMaterialsManager()
    const cache = getLocalCryptographicMaterialsCache(1)
    // A cache that deletes each entry one microtask after it is put.
    const evictingCache = {
      ...cache,
      putEncryptionMaterial(...args: [string, any, number, number?]) {
        cache.putEncryptionMaterial(...args)
        queueMicrotask(() => cache.del(args[0]))
      },
    }
    const cmm = cachingCMM(backing, { cache: evictingCache })

    const materials = await encryptConcurrently(cmm, times(10))

    expect(materials).to.have.lengthOf(10)
    expect(backing.calls.encrypt).to.equal(1)
  })

  it('waiting callers retry a failed request once', async () => {
    const backing = slowBackingMaterialsManager({ outcomes: ['fail', 'ok'] })
    const cmm = cachingCMM(backing)

    const results = await Promise.allSettled(startEncrypts(cmm, times(10)))

    expect(results.filter((r) => r.status === 'rejected')).to.have.lengthOf(1)
    expect(backing.calls.encrypt).to.equal(2)
  })

  it('a request that keeps failing reaches every caller after one retry', async () => {
    const backing = slowBackingMaterialsManager({ outcomes: ['fail'] })
    const cmm = cachingCMM(backing)

    const results = await Promise.allSettled(startEncrypts(cmm, times(10)))

    for (const result of results) {
      expect(result.status).to.equal('rejected')
      expect((result as PromiseRejectedResult).reason.message).to.equal(
        'backing materials manager unavailable'
      )
    }
    expect(backing.calls.encrypt).to.equal(2)
  })

  it('fails waiting callers after inFlightTTL when the request hangs', async () => {
    const backing = slowBackingMaterialsManager({ outcomes: ['hang'] })
    const cmm = cachingCMM(backing)

    const [, ...waiters] = startEncrypts(cmm, times(5))
    const results = await Promise.allSettled(waiters)

    for (const result of results) {
      expect((result as PromiseRejectedResult).reason.message).to.equal(
        'Caching materials manager inFlightTTL exceeded'
      )
    }
    expect(backing.calls.encrypt).to.equal(1)
  })

  it('starts another request for new callers once one hangs past graceInterval', async () => {
    const backing = slowBackingMaterialsManager({ outcomes: ['hang', 'ok'] })
    const cmm = cachingCMM(backing)

    startEncrypts(cmm, times(1))
    await new Promise((resolve) => setTimeout(resolve, FAST.graceInterval + 5))
    const materials = await encryptConcurrently(cmm, times(5))

    expect(materials).to.have.lengthOf(5)
    expect(backing.calls.encrypt).to.equal(2)
  })

  it('fails waiting callers when the response cannot be cached', async () => {
    const malformed = {
      async getEncryptionMaterials() {
        await new Promise((resolve) => setTimeout(resolve, 5))
        return { suite }
      },
      async decryptMaterials() {
        await new Promise((resolve) => setTimeout(resolve, 5))
        return { suite }
      },
    }
    const cmm = cachingCMM(malformed)

    const encrypts = await Promise.allSettled(startEncrypts(cmm, times(3)))
    const decrypts = await Promise.allSettled(
      Array.from({ length: 3 }, async () =>
        cmm.decryptMaterials(decryptRequest)
      )
    )

    for (const result of [...encrypts, ...decrypts]) {
      expect(result.status).to.equal('rejected')
    }
  })

  it('forgets a cache key once its requests finish', async () => {
    const backing = slowBackingMaterialsManager()
    const cache = getLocalCryptographicMaterialsCache(100)
    const cmm = cachingCMM(backing, { cache, maxMessagesEncrypted: 2 })

    await encryptConcurrently(cmm, times(5))
    await Promise.all(
      Array.from({ length: 5 }, async () =>
        cmm.decryptMaterials(decryptRequest)
      )
    )
    await Promise.allSettled(
      startEncrypts(
        cachingCMM(slowBackingMaterialsManager({ outcomes: ['fail'] }), {
          cache,
        }),
        times(3),
        { encryptionContext: { a: 'b' } }
      )
    )

    expect(batchesByCache.get(cache)?.size).to.equal(0)
  })

  it('forgets a request that never settles once a newer one starts', async () => {
    const backing = slowBackingMaterialsManager({ outcomes: ['hang', 'ok'] })
    const cache = getLocalCryptographicMaterialsCache(100)
    const cmm = cachingCMM(backing, { cache })

    startEncrypts(cmm, times(1))
    await new Promise((resolve) => setTimeout(resolve, FAST.graceInterval + 5))
    await encryptConcurrently(cmm, times(3))

    expect(batchesByCache.get(cache)?.size).to.equal(0)
  })

  it('does not export the shared request internals from the package', () => {
    expect(cacheMaterial).to.not.have.property('SHARED_REQUESTS')
    expect(cacheMaterial).to.not.have.property('batchesByCache')
  })

  describe('requests run in parallel when the response cannot serve another caller', () => {
    const uncached = {
      'plaintextLength exceeds maxBytesEncrypted': {
        backing: {},
        cmm: { maxBytesEncrypted: 10 },
        length: 11,
        request: {},
        peak: 10,
      },
      'two plaintexts exceed maxBytesEncrypted': {
        backing: {},
        cmm: { maxBytesEncrypted: 10 },
        length: 6,
        request: {},
        peak: 10,
      },
      'maxMessagesEncrypted is 1': {
        backing: {},
        cmm: { maxMessagesEncrypted: 1 },
        length: 1,
        request: {},
        peak: 10,
      },
      'the backing suite is not cache safe': {
        backing: { materialSuite: uncacheableSuite },
        cmm: {},
        length: 1,
        request: { suite: undefined },
        // The first response reveals the suite is not cache safe,
        // so the other 9 requests start after it, in parallel.
        peak: 9,
      },
    }

    for (const [
      name,
      { backing: options, cmm: limits, length, request, peak },
    ] of Object.entries(uncached)) {
      it(name, async () => {
        const backing = slowBackingMaterialsManager(options)
        const cmm = cachingCMM(backing, limits)

        const materials = await encryptConcurrently(
          cmm,
          times(10, length),
          request
        )

        expect(backing.calls.encrypt).to.equal(10)
        expect(backing.calls.peak).to.equal(peak)
        expect(usageByDataKey(materials, times(10, length))).to.have.lengthOf(
          10
        )
      })
    }
  })
})
