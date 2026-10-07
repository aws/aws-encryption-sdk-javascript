// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  cacheEntryHasExceededLimits,
  getEncryptionMaterials,
  decryptMaterials,
} from '../src/caching_cryptographic_materials_decorators'
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

// A backing materials manager that takes 5 ms per request
// and returns a new data key each time.
function slowBackingMaterialsManager({
  fail = false,
  materialSuite = suite,
} = {}) {
  const calls = { encrypt: 0, decrypt: 0, active: 0, peak: 0 }
  const respond = async () => {
    calls.active += 1
    calls.peak = Math.max(calls.peak, calls.active)
    await new Promise((resolve) => setTimeout(resolve, 5))
    calls.active -= 1
    if (fail) throw new Error('backing materials manager unavailable')
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

async function encryptConcurrently(cmm: any, count: number, request: any) {
  return Promise.all(
    Array.from({ length: count }, async () =>
      cmm.getEncryptionMaterials(request)
    )
  )
}

// Messages and bytes encrypted under each distinct data key.
function usageByDataKey(materials: any[], plaintextLength: number) {
  const usage = new Map<string, { messages: number; bytes: number }>()
  for (const material of materials) {
    const dataKey = Buffer.from(
      unwrapDataKey(material.getUnencryptedDataKey())
    ).toString('hex')
    const entry = usage.get(dataKey) || { messages: 0, bytes: 0 }
    entry.messages += 1
    entry.bytes += plaintextLength
    usage.set(dataKey, entry)
  }
  return [...usage.values()]
}

describe('caching materials manager: concurrent cache misses (#1665)', () => {
  it('concurrent encrypts share data keys without exceeding maxMessagesEncrypted', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing, { maxMessagesEncrypted: 5 })

    const materials = await encryptConcurrently(cmm, 10, encryptRequest)

    expect(backing.calls.encrypt).to.equal(2)
    expect(usageByDataKey(materials, 1).map((u) => u.messages)).to.deep.equal([
      5, 5,
    ])
  })

  it('concurrent encrypts share data keys without exceeding maxBytesEncrypted', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing, { maxBytesEncrypted: 10 })

    const materials = await encryptConcurrently(cmm, 10, {
      ...encryptRequest,
      plaintextLength: 3,
    })

    expect(backing.calls.encrypt).to.equal(4)
    expect(usageByDataKey(materials, 3).map((u) => u.bytes)).to.deep.equal([
      9, 9, 9, 3,
    ])
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

  it('fails every waiting caller on a failed request, and retries on the next call', async () => {
    const backing = slowBackingMaterialsManager({ fail: true })
    const cmm = cachingCMM(backing)

    const results = await Promise.allSettled(
      Array.from({ length: 10 }, async () =>
        cmm.getEncryptionMaterials(encryptRequest)
      )
    )
    expect(results.every((r) => r.status === 'rejected')).to.equal(true)
    expect(backing.calls.encrypt).to.equal(1)

    await cmm.getEncryptionMaterials(encryptRequest).catch(() => undefined)
    expect(backing.calls.encrypt).to.equal(2)
  })

  describe('requests run in parallel when the response is not cached', () => {
    const uncached = {
      'plaintextLength exceeds maxBytesEncrypted': {
        backing: {},
        cmm: { maxBytesEncrypted: 10 },
        request: { ...encryptRequest, plaintextLength: 11 },
        peak: 10,
      },
      'two plaintexts exceed maxBytesEncrypted': {
        backing: {},
        cmm: { maxBytesEncrypted: 10 },
        request: { ...encryptRequest, plaintextLength: 6 },
        peak: 10,
      },
      'maxMessagesEncrypted is 1': {
        backing: {},
        cmm: { maxMessagesEncrypted: 1 },
        request: encryptRequest,
        peak: 10,
      },
      'the backing suite is not cache safe': {
        backing: { materialSuite: uncacheableSuite },
        cmm: {},
        request: { encryptionContext: {}, plaintextLength: 1 },
        // The first response reveals the suite is not cache safe,
        // so the other 9 requests start after it, in parallel.
        peak: 9,
      },
    }

    for (const [
      name,
      { backing: options, cmm: limits, request, peak },
    ] of Object.entries(uncached)) {
      it(name, async () => {
        const backing = slowBackingMaterialsManager(options)
        const cmm = cachingCMM(backing, limits)

        const materials = await encryptConcurrently(cmm, 10, request)

        expect(backing.calls.encrypt).to.equal(10)
        expect(backing.calls.peak).to.equal(peak)
        expect(usageByDataKey(materials, 1)).to.have.lengthOf(10)
      })
    }
  })

  it('serves every caller when the entry is evicted while waiters resume', async () => {
    const backing = slowBackingMaterialsManager()
    // A cache that deletes each entry one microtask after it is put.
    const cache = getLocalCryptographicMaterialsCache(1)
    const evictingCache = {
      ...cache,
      putEncryptionMaterial(...args: [string, any, number, number?]) {
        cache.putEncryptionMaterial(...args)
        queueMicrotask(() => cache.del(args[0]))
      },
    }
    const cmm = cachingCMM(backing, { cache: evictingCache })

    const materials = await encryptConcurrently(cmm, 10, encryptRequest)

    expect(materials).to.have.lengthOf(10)
    for (const material of materials) {
      expect(material.hasUnencryptedDataKey).to.equal(true)
    }
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

    const encrypts = await Promise.allSettled(
      Array.from({ length: 3 }, async () =>
        cmm.getEncryptionMaterials(encryptRequest)
      )
    )
    const decrypts = await Promise.allSettled(
      Array.from({ length: 3 }, async () =>
        cmm.decryptMaterials(decryptRequest)
      )
    )

    for (const result of [...encrypts, ...decrypts]) {
      expect(result.status).to.equal('rejected')
    }
  })
})
