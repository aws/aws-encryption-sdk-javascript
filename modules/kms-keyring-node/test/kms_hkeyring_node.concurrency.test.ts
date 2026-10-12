// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  EncryptedDataKey,
  NodeBranchKeyMaterial,
  NodeDecryptionMaterial,
  NodeEncryptionMaterial,
  unwrapDataKey,
} from '@aws-crypto/material-management'
import {
  BRANCH_KEY_ID_A,
  BRANCH_KEY_ID_B,
  EC_A,
  EC_B,
  KEYSTORE,
  TEST_ESDK_ALG_SUITE,
  TTL,
} from './fixtures'
import {
  KmsHierarchicalKeyRingNode,
  KmsHierarchicalKeyRingStormTracking,
} from '../src/kms_hkeyring_node'
import {
  BRANCH_KEY_ID_SUPPLIER,
  deepCopyBranchKeyMaterial,
} from './kms_hkeyring_node.test'
import { expect } from 'chai'
import Sinon from 'sinon'
import {
  BranchKeyStoreNode,
  KeyStoreInfoOutput,
} from '@aws-crypto/branch-keystore-node'

import { getBranchKeyMaterials } from '../src/kms_hkeyring_node_helpers'
import {
  FetchToken,
  SHARED_FETCHES,
  StormTracker,
  StormTrackingSettings,
  sharedFetchesFor,
} from '../src/branch_key_storm_tracker'
import { getLocalCryptographicMaterialsCache } from '@aws-crypto/cache-material'
import { NodeAlgorithmSuite } from '@aws-crypto/material-management'
import { v4 } from 'uuid'

const CONCURRENCY = 25

let activeMaterialA: NodeBranchKeyMaterial
let activeMaterialB: NodeBranchKeyMaterial
before(async function () {
  activeMaterialA = await KEYSTORE.getActiveBranchKey(BRANCH_KEY_ID_A)
  activeMaterialB = await KEYSTORE.getActiveBranchKey(BRANCH_KEY_ID_B)
})

// A keystore stub that returns fresh material (its own buffer, as a real
// keystore would) and resolves on the microtask queue.
function stubKeyStore(): BranchKeyStoreNode {
  const keyStore = Sinon.createStubInstance(BranchKeyStoreNode)
  const forId = async (branchKeyId: string) =>
    deepCopyBranchKeyMaterial(
      branchKeyId === BRANCH_KEY_ID_A ? activeMaterialA : activeMaterialB
    )
  keyStore.getActiveBranchKey.callsFake(forId)
  // The two active versions are the only versions used here, so map by id.
  keyStore.getBranchKeyVersion.callsFake(forId)
  keyStore.getKeyStoreInfo.callsFake(
    (): KeyStoreInfoOutput => ({
      keystoreId: 'keyStoreId',
      keystoreTableName: 'keystoreTableName',
      logicalKeyStoreName: 'logicalKeyStoreName',
      grantTokens: [],
      kmsConfiguration: null as any,
    })
  )
  return keyStore
}

function newKeyring(maxCacheSize?: number): KmsHierarchicalKeyRingNode {
  return new KmsHierarchicalKeyRingNode({
    branchKeyIdSupplier: BRANCH_KEY_ID_SUPPLIER,
    keyStore: stubKeyStore(),
    cacheLimitTtl: TTL,
    maxCacheSize,
  })
}

describe('KmsHierarchicalKeyRingNode: concurrent cold-cache operations (#1691)', () => {
  it('concurrent onEncrypt does not wrap data keys under an evicted (zeroed) branch key', async () => {
    // maxCacheSize=1 + two branch keys => every alternating encrypt evicts the
    // other entry, zeroing its buffer.
    const hkr = newKeyring(1)
    const materials = Array.from(
      { length: CONCURRENCY },
      (_, i) =>
        new NodeEncryptionMaterial(
          TEST_ESDK_ALG_SUITE,
          i % 2 === 0 ? EC_A : EC_B
        )
    )

    await Promise.all(
      materials.map(async (m) => {
        await hkr.onEncrypt(m)
      })
    )

    const verifier = newKeyring()
    for (const m of materials) {
      const expectedPdk = unwrapDataKey(m.getUnencryptedDataKey())
      const decryptionMaterial = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        m.encryptionContext
      )
      await verifier.onDecrypt(decryptionMaterial, m.encryptedDataKeys)
      expect(
        unwrapDataKey(decryptionMaterial.getUnencryptedDataKey())
      ).to.deep.equal(expectedPdk)
    }
  })

  it('concurrent onDecrypt does not derive from an evicted (zeroed) branch key', async () => {
    // Build valid ciphertexts for both branch keys (sequential = uncorrupted).
    const setup = newKeyring()
    const encA = new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
    const encB = new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_B)
    await setup.onEncrypt(encA)
    await setup.onEncrypt(encB)

    const cases = [
      {
        edks: encA.encryptedDataKeys,
        ec: EC_A,
        pdk: unwrapDataKey(encA.getUnencryptedDataKey()),
      },
      {
        edks: encB.encryptedDataKeys,
        ec: EC_B,
        pdk: unwrapDataKey(encB.getUnencryptedDataKey()),
      },
    ]

    const hkr = newKeyring(1)
    const recovered = await Promise.all(
      Array.from({ length: CONCURRENCY }, async (_, i) => {
        const { edks, ec } = cases[i % 2]
        const decryptionMaterial = new NodeDecryptionMaterial(
          TEST_ESDK_ALG_SUITE,
          ec
        )
        await hkr.onDecrypt(decryptionMaterial, edks as EncryptedDataKey[])
        return unwrapDataKey(decryptionMaterial.getUnencryptedDataKey())
      })
    )

    for (let i = 0; i < recovered.length; i++) {
      expect(recovered[i]).to.deep.equal(cases[i % 2].pdk)
    }
  })
})

const CONCURRENT_OPERATIONS = 3000

// Shortened timings, so the tests run in milliseconds.
const FAST = { graceInterval: 40, sleepMilli: 2 }
const DEFAULT = { ...SHARED_FETCHES }
// Seconds, like the keyring option.
const FAST_STORM: KmsHierarchicalKeyRingStormTracking = {
  gracePeriod: 0.2,
  graceInterval: 0.04,
  inFlightTTL: 0.2,
}

// A keystore stub where each request takes `ms` milliseconds.
// `outcomes` decides each call in order: 'ok', 'fail', or 'hang'; later calls use the last one.
function slowKeyStore(
  ms = 5,
  outcomes: ('ok' | 'fail' | 'hang')[] = ['ok']
): Sinon.SinonStubbedInstance<BranchKeyStoreNode> & { peak: () => number } {
  const material = new NodeBranchKeyMaterial(
    Buffer.alloc(32, 1),
    BRANCH_KEY_ID_A,
    v4(),
    {}
  )
  const keyStore = stubKeyStore() as any
  let calls = 0
  let active = 0
  let peak = 0
  const fetch = async () => {
    const outcome = outcomes[Math.min(calls++, outcomes.length - 1)]
    if (outcome === 'hang') return new Promise<never>(() => undefined)
    peak = Math.max(peak, ++active)
    await new Promise((resolve) => setTimeout(resolve, ms))
    active -= 1
    if (outcome === 'fail') throw new Error('keystore unavailable')
    return deepCopyBranchKeyMaterial(material)
  }
  keyStore.getActiveBranchKey.callsFake(fetch)
  keyStore.getBranchKeyVersion.callsFake(fetch)
  keyStore.peak = () => peak
  return keyStore
}

function keyringFor(
  keyStore: BranchKeyStoreNode,
  {
    cache,
    partitionId,
    stormTracking,
  }: {
    cache?: KmsHierarchicalKeyRingNode['_cmc']
    partitionId?: string
    stormTracking?: KmsHierarchicalKeyRingStormTracking
  } = {}
): KmsHierarchicalKeyRingNode {
  return new KmsHierarchicalKeyRingNode({
    branchKeyIdSupplier: BRANCH_KEY_ID_SUPPLIER,
    keyStore,
    cacheLimitTtl: TTL,
    cache,
    partitionId,
    stormTracking,
  })
}

// A minimal keyring for calling getBranchKeyMaterials directly.
function hKeyringFor(keyStore: any, stormTracking?: StormTrackingSettings) {
  return {
    keyStore,
    cacheLimitTtl: TTL * 1000,
    cacheEntryHasExceededLimits: () => false,
    _stormTracking: stormTracking,
  } as any
}

function startEncrypts(hkr: KmsHierarchicalKeyRingNode, count: number) {
  return Array.from({ length: count }, async () =>
    hkr.onEncrypt(new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A))
  )
}

async function encryptConcurrently(
  hkr: KmsHierarchicalKeyRingNode,
  count: number
) {
  return Promise.all(startEncrypts(hkr, count))
}

async function encryptSettled(hkr: KmsHierarchicalKeyRingNode, count: number) {
  return Promise.allSettled(startEncrypts(hkr, count))
}

const wait = async (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms))

describe('KmsHierarchicalKeyRingNode: shared keystore fetches (#1663)', () => {
  beforeEach(() => Object.assign(SHARED_FETCHES, FAST))
  afterEach(() => Object.assign(SHARED_FETCHES, DEFAULT))

  it(`${CONCURRENT_OPERATIONS} concurrent onEncrypt misses share one keystore call`, async () => {
    const keyStore = slowKeyStore()
    await encryptConcurrently(keyringFor(keyStore), CONCURRENT_OPERATIONS)
    expect(keyStore.getActiveBranchKey.callCount).to.equal(1)
  })

  it(`${CONCURRENT_OPERATIONS} concurrent onDecrypt misses share one keystore call`, async () => {
    const keyStore = slowKeyStore()
    const [encrypted] = await encryptConcurrently(keyringFor(keyStore), 1)
    const expectedPdk = unwrapDataKey(encrypted.getUnencryptedDataKey())

    const hkr = keyringFor(keyStore)
    const recovered = await Promise.all(
      Array.from({ length: CONCURRENT_OPERATIONS }, async () => {
        const material = new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
        await hkr.onDecrypt(material, encrypted.encryptedDataKeys)
        return unwrapDataKey(material.getUnencryptedDataKey())
      })
    )

    expect(keyStore.getBranchKeyVersion.callCount).to.equal(1)
    for (const pdk of recovered) expect(pdk).to.deep.equal(expectedPdk)
  })

  it('keyrings that share a cache and partition share keystore calls', async () => {
    const keyStore = slowKeyStore()
    const cache = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(100)
    const partitionId = v4()
    await Promise.all([
      encryptConcurrently(keyringFor(keyStore, { cache, partitionId }), 10),
      encryptConcurrently(keyringFor(keyStore, { cache, partitionId }), 10),
    ])
    expect(keyStore.getActiveBranchKey.callCount).to.equal(1)
  })

  it('waiting callers make their own fetch when the shared one fails', async () => {
    const keyStore = slowKeyStore(5, ['fail', 'ok'])
    const results = await encryptSettled(keyringFor(keyStore), 10)

    // Only the caller whose fetch failed sees the error, as without sharing.
    expect(results.filter((r) => r.status === 'rejected')).to.have.lengthOf(1)
    expect(keyStore.getActiveBranchKey.callCount).to.equal(10)
  })

  it('a failing keystore fails each caller with its own error', async () => {
    const keyStore = slowKeyStore(5, ['fail'])
    const results = await encryptSettled(keyringFor(keyStore), 10)

    for (const result of results) {
      expect((result as PromiseRejectedResult).reason.message).to.equal(
        'keystore unavailable'
      )
    }
    expect(keyStore.getActiveBranchKey.callCount).to.equal(10)
  })

  it('waiting callers do not time out', async () => {
    // Slower than the storm tracking inFlightTTL used below; every caller still succeeds.
    const keyStore = slowKeyStore(250)
    await encryptConcurrently(keyringFor(keyStore), 10)
    expect(keyStore.getActiveBranchKey.callCount).to.equal(1)
  })

  it('starts another fetch for new callers once one hangs past graceInterval', async () => {
    const keyStore = slowKeyStore(5, ['hang', 'ok'])
    const hkr = keyringFor(keyStore)

    startEncrypts(hkr, 1)
    await wait(FAST.graceInterval + 5)
    await encryptConcurrently(hkr, 5)

    expect(keyStore.getActiveBranchKey.callCount).to.equal(2)
  })

  it('a stale fetch that fails late does not affect callers waiting on a newer one', async () => {
    const deferreds: {
      resolve: (m: NodeBranchKeyMaterial) => void
      reject: (e: Error) => void
    }[] = []
    const keyStore = {
      getBranchKeyVersion: async () =>
        new Promise<NodeBranchKeyMaterial>((resolve, reject) =>
          deferreds.push({ resolve, reject })
        ),
    }
    const cache = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(100)
    const get = async () =>
      getBranchKeyMaterials(
        hKeyringFor(keyStore),
        cache,
        BRANCH_KEY_ID_A,
        'entry',
        'version'
      )

    const stale = get()
    await wait(FAST.graceInterval + 5)
    const newer = [get(), get(), get()]
    await wait(1)
    expect(deferreds).to.have.lengthOf(2)

    deferreds[0].reject(new Error('stale'))
    const [staleResult] = await Promise.allSettled([stale])
    expect((staleResult as PromiseRejectedResult).reason.message).to.equal(
      'stale'
    )
    deferreds[1].resolve(
      new NodeBranchKeyMaterial(Buffer.alloc(32, 7), BRANCH_KEY_ID_A, v4(), {})
    )
    for (const result of await Promise.all(newer)) {
      expect(result.branchKey()).to.deep.equal(Buffer.alloc(32, 7))
    }
    expect(deferreds).to.have.lengthOf(2)
  })

  it('has no limit on branch keys fetched at once', async () => {
    const keyStore = slowKeyStore(20)
    const cache = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(100)
    const hKeyring = hKeyringFor(keyStore)

    await Promise.all(
      Array.from({ length: 30 }, async (_, i) =>
        getBranchKeyMaterials(hKeyring, cache, BRANCH_KEY_ID_A, `id-${i}`, 'v')
      )
    )

    expect(keyStore.peak()).to.equal(30)
  })

  it('forgets a cache entry once its fetches settle', async () => {
    const cache = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(100)
    await encryptConcurrently(keyringFor(slowKeyStore(), { cache }), 5)
    await encryptSettled(keyringFor(slowKeyStore(5, ['fail']), { cache }), 5)
    expect(sharedFetchesFor(cache)?.size).to.equal(0)
  })

  it('does not refresh an entry before it expires', async () => {
    const clock = Sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] })
    try {
      const keyStore = slowKeyStore(20)
      const hkr = keyringFor(keyStore)
      await encryptConcurrently(hkr, 1)
      clock.tick(TTL * 1000 - 1)

      await encryptConcurrently(hkr, 10)
      expect(keyStore.getActiveBranchKey.callCount).to.equal(1)
    } finally {
      clock.restore()
    }
  })
})

describe('KmsHierarchicalKeyRingNode: stormTracking', () => {
  beforeEach(() => Object.assign(SHARED_FETCHES, FAST))
  afterEach(() => Object.assign(SHARED_FETCHES, DEFAULT))

  it('concurrent misses share one keystore call', async () => {
    const keyStore = slowKeyStore()
    await encryptConcurrently(
      keyringFor(keyStore, { stormTracking: FAST_STORM }),
      100
    )
    expect(keyStore.getActiveBranchKey.callCount).to.equal(1)
  })

  it('after a failed fetch, one waiting caller fetches again once it is graceInterval old', async () => {
    const keyStore = slowKeyStore(5, ['fail', 'ok'])
    const results = await encryptSettled(
      keyringFor(keyStore, { stormTracking: FAST_STORM }),
      10
    )

    expect(results.filter((r) => r.status === 'rejected')).to.have.lengthOf(1)
    expect(keyStore.getActiveBranchKey.callCount).to.equal(2)
  })

  it('starts another fetch when the first hangs past graceInterval', async () => {
    const keyStore = slowKeyStore(5, ['hang', 'ok'])
    const hkr = keyringFor(keyStore, { stormTracking: FAST_STORM })

    // The first caller's fetch never returns; the other 9 must not wait on it.
    const [, ...waiters] = startEncrypts(hkr, 10)
    const results = await Promise.allSettled(waiters)

    expect(keyStore.getActiveBranchKey.callCount).to.equal(2)
    for (const result of results) expect(result.status).to.equal('fulfilled')
  })

  it('fails waiting callers after inFlightTTL when every fetch hangs', async () => {
    const keyStore = slowKeyStore(5, ['hang'])
    const hkr = keyringFor(keyStore, { stormTracking: FAST_STORM })
    // Each caller told to fetch hangs forever; every other caller fails after inFlightTTL.
    const failures: string[] = []
    for (const p of startEncrypts(hkr, 10)) {
      p.catch((e) => failures.push(e.message))
    }
    const inFlightTTL = (FAST_STORM.inFlightTTL as number) * 1000
    const graceInterval = (FAST_STORM.graceInterval as number) * 1000
    await wait(2 * inFlightTTL)

    const fetchers = keyStore.getActiveBranchKey.callCount
    expect(fetchers).to.be.at.most(inFlightTTL / graceInterval + 1)
    expect(failures).to.have.lengthOf(10 - fetchers)
    for (const message of failures) {
      expect(message).to.equal('Storm cache inFlightTTL exceeded')
    }
  })

  it('fetches at most fanOut keys at once', async () => {
    const keyStore = slowKeyStore(20)
    const cache = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(100)
    const hKeyring = hKeyringFor(keyStore, {
      gracePeriod: 200,
      graceInterval: 40,
      inFlightTTL: 200,
      fanOut: 2,
    })

    await Promise.all(
      ['a', 'b', 'c', 'd'].map(async (id) =>
        getBranchKeyMaterials(hKeyring, cache, BRANCH_KEY_ID_A, id, 'version')
      )
    )

    expect(keyStore.getBranchKeyVersion.callCount).to.equal(4)
    expect(keyStore.peak()).to.equal(2)
  })

  it('refreshes an entry in its grace period with one fetch while others use it', async () => {
    const clock = Sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] })
    try {
      const keyStore = slowKeyStore(20)
      const gracePeriod = 10 // seconds
      const hkr = keyringFor(keyStore, { stormTracking: { gracePeriod } })
      await encryptConcurrently(hkr, 1)
      clock.tick(TTL * 1000 - (gracePeriod * 1000) / 2)

      let finished = 0
      const all = Promise.all(
        startEncrypts(hkr, 10).map(async (p) => {
          await p
          finished += 1
        })
      )
      // The refresh takes 20 ms; the other 9 callers use the cached entry meanwhile.
      await wait(5)
      expect(finished).to.equal(9)

      await all
      expect(keyStore.getActiveBranchKey.callCount).to.equal(2)
    } finally {
      clock.restore()
    }
  })

  it('uses the cached entry when an early refresh fails', async () => {
    const clock = Sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] })
    try {
      const keyStore = slowKeyStore(5, ['ok', 'fail'])
      const gracePeriod = 10 // seconds
      const hkr = keyringFor(keyStore, { stormTracking: { gracePeriod } })
      await encryptConcurrently(hkr, 1)
      clock.tick(TTL * 1000 - (gracePeriod * 1000) / 2)

      await encryptConcurrently(hkr, 1)
      expect(keyStore.getActiveBranchKey.callCount).to.equal(2)
    } finally {
      clock.restore()
    }
  })
})

describe('StormTracker', () => {
  const settings = {
    gracePeriod: 10000,
    graceInterval: 1000,
    fanOut: 20,
    inFlightTTL: 10000,
  }

  it('only the newest fetch for an entry marks it fetched', () => {
    const tracker = new StormTracker()
    const stale = tracker.checkNewEntry('id', 0, settings)
    const newer = tracker.checkNewEntry('id', 1000, settings)
    expect(stale.state).to.equal('fetch')
    expect(newer.state).to.equal('fetch')

    // The stale fetch finishing late leaves the newer one in flight.
    tracker.fetched('id', stale.token as FetchToken)
    expect(tracker.checkNewEntry('id', 1001, settings).state).to.equal('wait')

    tracker.fetched('id', newer.token as FetchToken)
    expect(tracker.checkNewEntry('id', 1002, settings).state).to.equal('fetch')
  })

  it('a failed fetch stays in flight until graceInterval, like the MPL', () => {
    const tracker = new StormTracker()
    tracker.checkNewEntry('id', 0, settings)
    expect(tracker.checkNewEntry('id', 999, settings).state).to.equal('wait')
    expect(tracker.checkNewEntry('id', 1000, settings).state).to.equal('fetch')
  })

  it('forgets fetches older than inFlightTTL once fanOut is reached', () => {
    const tracker = new StormTracker()
    const small = { ...settings, fanOut: 1 }
    tracker.checkNewEntry('a', 2000, small)
    expect(tracker.checkNewEntry('b', 2000, small).state).to.equal('wait')
    expect(
      tracker.checkNewEntry('b', 2000 + small.inFlightTTL, small).state
    ).to.equal('fetch')
    expect(tracker.inFlightCount()).to.equal(1)
  })
})

describe('getBranchKeyMaterials: eviction while a request settles', () => {
  const material = (fill: number) =>
    new NodeBranchKeyMaterial(Buffer.alloc(32, fill), BRANCH_KEY_ID_A, v4(), {})

  function hKeyringWith(keyStore: any) {
    return {
      keyStore,
      cacheLimitTtl: TTL,
      cacheEntryHasExceededLimits: () => false,
    } as any
  }

  it('returns an intact branch key when another put evicts the entry before callers resume', async () => {
    const cache = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(1)
    // Another branch key is cached one microtask after this one,
    // which evicts and zeroes this entry in the one-entry cache.
    const racingCache = {
      ...cache,
      putBranchKeyMaterial(
        key: string,
        m: NodeBranchKeyMaterial,
        ttl?: number
      ) {
        cache.putBranchKeyMaterial(key, m, ttl)
        queueMicrotask(() => cache.putBranchKeyMaterial('other', material(2)))
      },
    }
    const keyStore = { getBranchKeyVersion: async () => material(1) }

    const results = await Promise.all(
      Array.from({ length: 3 }, async () =>
        getBranchKeyMaterials(
          hKeyringWith(keyStore),
          racingCache,
          BRANCH_KEY_ID_A,
          'entry',
          'version'
        )
      )
    )

    for (const result of results) {
      expect(result.branchKey()).to.deep.equal(Buffer.alloc(32, 1))
    }
  })

  it('returns intact branch keys for two keys racing through a one-entry cache', async () => {
    const cache = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(1)
    const keyStore = {
      getBranchKeyVersion: async (id: string) =>
        material(id === BRANCH_KEY_ID_A ? 1 : 2),
    }

    const results = await Promise.all(
      Array.from({ length: 10 }, async (_, i) =>
        getBranchKeyMaterials(
          hKeyringWith(keyStore),
          cache,
          i % 2 ? BRANCH_KEY_ID_B : BRANCH_KEY_ID_A,
          i % 2 ? 'entry-b' : 'entry-a',
          'version'
        )
      )
    )

    results.forEach((result, i) =>
      expect(result.branchKey()).to.deep.equal(Buffer.alloc(32, i % 2 ? 2 : 1))
    )
  })
})
