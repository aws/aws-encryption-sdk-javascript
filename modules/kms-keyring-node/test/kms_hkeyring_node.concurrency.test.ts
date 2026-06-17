// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { expect } from 'chai'
import { getBranchKeyMaterials } from '../src/kms_hkeyring_node_helpers'
import { getLocalCryptographicMaterialsCache } from '@aws-crypto/cache-material'
import {
  NodeAlgorithmSuite,
  NodeBranchKeyMaterial,
} from '@aws-crypto/material-management'
import { v4 } from 'uuid'

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
