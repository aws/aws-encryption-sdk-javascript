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

// Regression tests for #1691. Before the fix, getBranchKeyMaterials returned the
// cached NodeBranchKeyMaterial by reference. The CMC zeroes a material's buffer
// in place on eviction, so a concurrent operation that evicted an entry could
// zero the branch key another in-flight operation was about to derive from.
//
// The trigger is co-resolution: two branch-key fetches completing in the same
// event-loop tick, so one operation's cache write (and its eviction) lands
// between another operation's fetch and its synchronous wrap/unwrap. A stubbed
// keystore resolves on the microtask queue, which reproduces that deterministically
// (a real DDB+KMS fetch resolves on a later macrotask, so the window is far
// harder to hit in practice -- but the fix must hold regardless). maxCacheSize=1
// with two branch keys forces an eviction on every alternating operation.

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

    // Every EDK must round-trip. A buffer zeroed mid-wrap produces an EDK bound
    // to an all-zero key, which fails to decrypt under the real branch key.
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
