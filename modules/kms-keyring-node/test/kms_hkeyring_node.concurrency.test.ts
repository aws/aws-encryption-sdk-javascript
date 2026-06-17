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

const CONCURRENT_DECRYPTS = 3000
const CACHE_LIMIT_TTL = 60_000
const CACHE_ENTRY_ID = 'shared-cache-entry-id'

function fixtureMaterial(): NodeBranchKeyMaterial {
  return new NodeBranchKeyMaterial(Buffer.alloc(32), 'branchKeyId', v4(), {})
}

describe('KmsHierarchicalKeyRingNode: concurrent branch key retrieval', () => {
  it(`coalesces ${CONCURRENT_DECRYPTS} concurrent cache misses into one keystore call`, async () => {
    let getBranchKeyVersionCalls = 0
    const keyStore = {
      async getBranchKeyVersion() {
        getBranchKeyVersionCalls += 1
        await new Promise((resolve) => setTimeout(resolve, 5))
        return fixtureMaterial()
      },
    }

    const cmc = getLocalCryptographicMaterialsCache<NodeAlgorithmSuite>(100)
    const hKeyring = {
      keyStore,
      cacheLimitTtl: CACHE_LIMIT_TTL,
      cacheEntryHasExceededLimits: () => false,
      _branchKeyMaterialsInFlight: new Map(),
    } as any

    await Promise.all(
      Array.from({ length: CONCURRENT_DECRYPTS }, () =>
        getBranchKeyMaterials(
          hKeyring,
          cmc,
          'branchKeyId',
          CACHE_ENTRY_ID,
          'branchKeyVersion'
        )
      )
    )

    expect(getBranchKeyVersionCalls).to.equal(1)
  })
})
