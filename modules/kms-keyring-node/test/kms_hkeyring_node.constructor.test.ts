// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { BranchKeyStoreNode } from '@aws-crypto/branch-keystore-node'
import {
  DDB_TABLE_NAME,
  LOGICAL_KEYSTORE_NAME,
  KEY_ARN,
  BRANCH_KEY_ID,
  TTL,
} from './fixtures'
import { KmsHierarchicalKeyRingNode } from '../src/kms_hkeyring_node'
import { expect } from 'chai'
import { BranchKeyIdSupplier } from '@aws-crypto/kms-keyring'
import { EncryptionContext } from '@aws-crypto/material-management'

class DummyBranchKeyIdSupplier implements BranchKeyIdSupplier {
  getBranchKeyId(encryptionContext: EncryptionContext): string {
    return encryptionContext[''] ? encryptionContext[''] : ''
  }
}

const branchKeyId = BRANCH_KEY_ID
const cacheLimitTtl = TTL
const maxCacheSize = 1000
const keyStore = new BranchKeyStoreNode({
  storage: { ddbTableName: DDB_TABLE_NAME },
  logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
  kmsConfiguration: { identifier: KEY_ARN },
})
const branchKeyIdSupplier = new DummyBranchKeyIdSupplier()
const hkr = new KmsHierarchicalKeyRingNode({
  branchKeyId,
  branchKeyIdSupplier,
  keyStore,
  cacheLimitTtl,
  maxCacheSize,
})

describe('KmsHierarchicalKeyRingNode: constructor', () => {
  describe('Runtime type checks', () => {
    const truthyValues = [1, 'string', true, {}, [], -1, 0.21]
    const falseyValues = [false, 0, 0n, -0, 0x0, '', null, undefined, NaN]
    const nonStringFilter = (v: any) => typeof v !== 'string'
    const nonNumberFilter = (v: any) => typeof v !== 'number'

    it('Precondition: The branch key id must be a string', () => {
      const nonStringFalseyValues = falseyValues.filter(nonStringFilter)
      for (const branchKeyId of nonStringFalseyValues) {
        const hkr = new KmsHierarchicalKeyRingNode({
          branchKeyId: branchKeyId as any,
          branchKeyIdSupplier,
          keyStore,
          cacheLimitTtl,
        })
        expect(hkr.branchKeyId).to.equal(undefined)
      }

      const nonStringTruthyValues = truthyValues.filter(nonStringFilter)
      for (const branchKeyId of nonStringTruthyValues) {
        expect(
          () =>
            new KmsHierarchicalKeyRingNode({
              branchKeyId: branchKeyId as any,
              branchKeyIdSupplier,
              keyStore,
              cacheLimitTtl,
            })
        ).to.throw('The branch key id must be a string')
      }
    })

    it('Precondition: The branch key id supplier must be a BranchKeyIdSupplier', () => {
      for (const branchKeyIdSupplier of falseyValues) {
        const hkr = new KmsHierarchicalKeyRingNode({
          branchKeyIdSupplier: branchKeyIdSupplier as any,
          branchKeyId,
          keyStore,
          cacheLimitTtl,
        })
        expect(hkr.branchKeyIdSupplier).to.equal(undefined)
      }

      for (const branchKeyIdSupplier of truthyValues) {
        expect(
          () =>
            new KmsHierarchicalKeyRingNode({
              branchKeyIdSupplier: branchKeyIdSupplier as any,
              branchKeyId,
              keyStore,
              cacheLimitTtl,
            })
        ).to.throw('The branch key id supplier must be a BranchKeyIdSupplier')
      }
    })

    it('Precondition: The keystore must be a BranchKeyStore', () => {
      for (const keyStore of [...truthyValues, ...falseyValues]) {
        expect(
          () =>
            new KmsHierarchicalKeyRingNode({
              branchKeyId,
              keyStore: keyStore as any,
              cacheLimitTtl,
            })
        ).to.throw('The keystore must be a BranchKeyStore')
      }
    })

    it('Precondition: The cache limit TTL must be a number', () => {
      const ttls = [...falseyValues, ...truthyValues].filter(nonNumberFilter)
      for (const cacheLimitTtl of ttls) {
        expect(
          () =>
            new KmsHierarchicalKeyRingNode({
              branchKeyId,
              keyStore,
              cacheLimitTtl: cacheLimitTtl as any,
            })
        ).to.throw('The cache limit TTL must be a number')
      }
    })

    it('Precondition: The max cache size must be a number', () => {
      for (const maxCacheSize of falseyValues.filter(nonNumberFilter)) {
        const hkr = new KmsHierarchicalKeyRingNode({
          branchKeyId,
          keyStore,
          cacheLimitTtl,
          maxCacheSize: maxCacheSize as any,
        })
        expect(hkr.maxCacheSize).to.equal(1000)
      }

      for (const maxCacheSize of truthyValues.filter(nonNumberFilter)) {
        expect(
          () =>
            new KmsHierarchicalKeyRingNode({
              branchKeyId,
              keyStore,
              cacheLimitTtl,
              maxCacheSize: maxCacheSize as any,
            })
        ).to.throw('The max cache size must be a number')
      }

      expect(
        new KmsHierarchicalKeyRingNode({
          branchKeyId,
          keyStore,
          cacheLimitTtl,
          maxCacheSize: 0,
        }).maxCacheSize
      ).to.equal(0)
    })
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl
  //= type=test
  //# The maximum amount of time in seconds that an entry within the cache may be used before it MUST be evicted.
  //# The client MUST set a time-to-live (TTL) for [branch key materials](../structures.md#branch-key-materials) in the underlying cache.
  //# This value MUST be greater than zero.
  it('Precondition: Cache limit TTL must be non-negative and less than or equal to (Number.MAX_SAFE_INTEGER / 1000) seconds', () => {
    expect(
      new KmsHierarchicalKeyRingNode({
        branchKeyId,
        keyStore,
        cacheLimitTtl: 0,
      }).cacheLimitTtl
    ).to.equal(0)

    expect(
      new KmsHierarchicalKeyRingNode({
        branchKeyId,
        keyStore,
        cacheLimitTtl: Number.MAX_SAFE_INTEGER / 1000,
      }).cacheLimitTtl
    ).to.equal((Number.MAX_SAFE_INTEGER / 1000) * 1000)

    expect(
      () =>
        new KmsHierarchicalKeyRingNode({
          branchKeyId,
          keyStore,
          cacheLimitTtl: -1,
        })
    ).to.throw(
      'Cache limit TTL must be non-negative and less than or equal to (Number.MAX_SAFE_INTEGER / 1000) seconds'
    )

    expect(
      () =>
        new KmsHierarchicalKeyRingNode({
          branchKeyId,
          keyStore,
          cacheLimitTtl: Number.MAX_SAFE_INTEGER / 1000 + 1,
        })
    ).to.throw(
      'Cache limit TTL must be non-negative and less than or equal to (Number.MAX_SAFE_INTEGER / 1000) seconds'
    )
  })

  it('Precondition: Must provide a branch key identifier or supplier', () => {
    expect(
      () =>
        new KmsHierarchicalKeyRingNode({
          keyStore,
          cacheLimitTtl,
        })
    ).to.throw('Must provide a branch key identifier or supplier')
  })

  it('Precondition: Max cache size must be non-negative and less than or equal Number.MAX_SAFE_INTEGER', () => {
    expect(
      new KmsHierarchicalKeyRingNode({
        branchKeyId,
        keyStore,
        cacheLimitTtl,
        maxCacheSize: 0,
      }).maxCacheSize
    ).to.equal(0)

    expect(
      new KmsHierarchicalKeyRingNode({
        branchKeyId,
        keyStore,
        cacheLimitTtl,
        maxCacheSize: Number.MAX_SAFE_INTEGER,
      }).maxCacheSize
    ).to.equal(Number.MAX_SAFE_INTEGER)

    expect(
      () =>
        new KmsHierarchicalKeyRingNode({
          branchKeyId,
          keyStore,
          cacheLimitTtl,
          maxCacheSize: -1,
        })
    ).to.throw(
      'Max cache size must be non-negative and less than or equal Number.MAX_SAFE_INTEGER'
    )

    expect(
      () =>
        new KmsHierarchicalKeyRingNode({
          branchKeyId,
          keyStore,
          cacheLimitTtl,
          maxCacheSize: Number.MAX_SAFE_INTEGER + 1,
        })
    ).to.throw(
      'Max cache size must be non-negative and less than or equal Number.MAX_SAFE_INTEGER'
    )
  })

  it('Postcondition: The keystore object is frozen', () => {
    expect(Object.isFrozen(hkr.keyStore)).equals(true)
  })

  it('Postcondition: Provided branch key supplier must be frozen', () => {
    expect(Object.isFrozen(hkr.branchKeyIdSupplier)).equals(true)
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#initialization
  //= type=test
  //# If no max cache size is provided, the cryptographic materials cache MUST be configured to a
  //# max cache size of 1000.
  it('Postcondition: The max cache size is initialized', () => {
    expect(
      new KmsHierarchicalKeyRingNode({
        branchKeyId,
        keyStore,
        cacheLimitTtl,
      }).maxCacheSize
    ).to.equal(maxCacheSize)
  })

  it('Postcondition: The HKR object must be frozen', () => {
    expect(Object.isFrozen(hkr)).equals(true)
  })

  it('All attributes initialized correctly', () => {
    expect(hkr.branchKeyId).to.equal(branchKeyId)
    expect(hkr.branchKeyIdSupplier).to.equal(branchKeyIdSupplier)
    expect(hkr.keyStore).to.equal(keyStore)
    expect(hkr.cacheLimitTtl).to.equal(cacheLimitTtl * 1000)
    expect(hkr.maxCacheSize).to.equal(maxCacheSize)
  })
})
