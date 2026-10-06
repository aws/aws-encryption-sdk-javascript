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
import { KmsHierarchicalKeyRingNode } from '../src/kms_hkeyring_node'
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

// A keystore stub that takes a few milliseconds per request,
// so concurrent operations all miss the cache before the first request returns.
function slowKeyStore(
  fail = false
): Sinon.SinonStubbedInstance<BranchKeyStoreNode> {
  const material = new NodeBranchKeyMaterial(
    Buffer.alloc(32, 1),
    BRANCH_KEY_ID_A,
    v4(),
    {}
  )
  const keyStore =
    stubKeyStore() as Sinon.SinonStubbedInstance<BranchKeyStoreNode>
  const fetch = async () => {
    await new Promise((resolve) => setTimeout(resolve, 5))
    if (fail) throw new Error('keystore unavailable')
    return deepCopyBranchKeyMaterial(material)
  }
  keyStore.getActiveBranchKey.callsFake(fetch)
  keyStore.getBranchKeyVersion.callsFake(fetch)
  return keyStore
}

function keyringFor(
  keyStore: BranchKeyStoreNode,
  cache?: KmsHierarchicalKeyRingNode['_cmc'],
  partitionId?: string
): KmsHierarchicalKeyRingNode {
  return new KmsHierarchicalKeyRingNode({
    branchKeyIdSupplier: BRANCH_KEY_ID_SUPPLIER,
    keyStore,
    cacheLimitTtl: TTL,
    cache,
    partitionId,
  })
}

async function encryptConcurrently(
  hkr: KmsHierarchicalKeyRingNode,
  count: number
) {
  return Promise.all(
    Array.from({ length: count }, async () =>
      hkr.onEncrypt(new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A))
    )
  )
}

describe('KmsHierarchicalKeyRingNode: concurrent branch key cache misses (#1663)', () => {
  it(`coalesces ${CONCURRENT_OPERATIONS} concurrent onEncrypt misses into one keystore call`, async () => {
    const keyStore = slowKeyStore()
    await encryptConcurrently(keyringFor(keyStore), CONCURRENT_OPERATIONS)
    expect(keyStore.getActiveBranchKey.callCount).to.equal(1)
  })

  it(`coalesces ${CONCURRENT_OPERATIONS} concurrent onDecrypt misses into one keystore call`, async () => {
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

  it('coalesces misses across keyrings that share a cache and partition', async () => {
    const keyStore = slowKeyStore()
    const cache = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(100)
    const partitionId = v4()
    await Promise.all([
      encryptConcurrently(keyringFor(keyStore, cache, partitionId), 10),
      encryptConcurrently(keyringFor(keyStore, cache, partitionId), 10),
    ])
    expect(keyStore.getActiveBranchKey.callCount).to.equal(1)
  })

  it('fails every waiting operation on a failed request, and retries on the next call', async () => {
    const keyStore = slowKeyStore(true)
    const hkr = keyringFor(keyStore)

    const results = await Promise.allSettled(
      Array.from({ length: 10 }, async () =>
        hkr.onEncrypt(new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A))
      )
    )
    expect(results.every((r) => r.status === 'rejected')).to.equal(true)
    expect(keyStore.getActiveBranchKey.callCount).to.equal(1)

    await hkr
      .onEncrypt(new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A))
      .catch(() => undefined)
    expect(keyStore.getActiveBranchKey.callCount).to.equal(2)
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
    // Another operation's put lands one microtask after this request's put.
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
