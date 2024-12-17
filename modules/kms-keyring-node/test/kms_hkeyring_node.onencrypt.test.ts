// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeBranchKeyMaterial,
  NodeEncryptionMaterial,
} from '@aws-crypto/material-management'
import { KmsHierarchicalKeyRingNode } from '../src/kms_hkeyring_node'
import chai, { expect } from 'chai'
import {
  ALG_SUITES,
  BRANCH_KEY_ID_A,
  BRANCH_KEY_ID_B,
  DEFAULT_EC,
  EC_A,
  EC_B,
  KEYSTORE,
  TEST_ESDK_ALG_SUITE,
  TTL,
} from './fixtures'
import chaiAsPromised from 'chai-as-promised'
import Sinon from 'sinon'
import { KMSClient } from '@aws-sdk/client-kms'
import { DynamoDBClient } from '@aws-sdk/client-dynamodb'
import {
  BRANCH_KEY_ID_SUPPLIER,
  deepCopyBranchKeyMaterial,
  testOnEncrypt,
  testOnEncryptError,
} from './kms_hkeyring_node.test'
import {
  BranchKeyStoreNode,
  KeyStoreInfoOutput,
} from '@aws-crypto/branch-keystore-node'
chai.use(chaiAsPromised)

const branchKeyIdA = BRANCH_KEY_ID_A
const branchKeyIdB = BRANCH_KEY_ID_B
const branchKeyIdSupplier = BRANCH_KEY_ID_SUPPLIER
const originalKeyStore = KEYSTORE
const cacheLimitTtl = TTL

// before running any tests, get the active branch key material for both branch
// key ids
let activeBranchKeyMaterialA: NodeBranchKeyMaterial
let activeBranchKeyMaterialB: NodeBranchKeyMaterial
before(async () => {
  activeBranchKeyMaterialA = await originalKeyStore.getActiveBranchKey(
    branchKeyIdA
  )
  activeBranchKeyMaterialB = await originalKeyStore.getActiveBranchKey(
    branchKeyIdB
  )
})

describe('KmsHierarchicalKeyRingNode: onEncrypt', () => {
  // mocking the real keystore
  let keyStore: Sinon.SinonStubbedInstance<BranchKeyStoreNode>
  let kmsSendSpy: Sinon.SinonSpy
  let ddbSendSpy: Sinon.SinonSpy
  let clock: Sinon.SinonFakeTimers

  // what to do before each test
  beforeEach(() => {
    // mock keystore
    keyStore = Sinon.createStubInstance(BranchKeyStoreNode)
    // spies to count network calls
    kmsSendSpy = Sinon.spy(KMSClient.prototype, 'send')
    ddbSendSpy = Sinon.spy(DynamoDBClient.prototype, 'send')
    // a clock to simulate TTL stalls
    clock = Sinon.useFakeTimers()

    // mock get active branch key material
    keyStore.getActiveBranchKey.callsFake(async (branchKeyId: string) => {
      if (branchKeyId === branchKeyIdA) {
        kmsSendSpy.callCount += 1
        ddbSendSpy.callCount += 1
        return deepCopyBranchKeyMaterial(activeBranchKeyMaterialA)
      } else if (branchKeyId === branchKeyIdB) {
        kmsSendSpy.callCount += 1
        ddbSendSpy.callCount += 1
        return deepCopyBranchKeyMaterial(activeBranchKeyMaterialB)
      } else {
        ddbSendSpy.callCount += 1
        throw new Error(
          `A branch key record with branch-key-id=${branchKeyId} and type=branch:ACTIVE was not found in DynamoDB`
        )
      }
    })

    keyStore.getKeyStoreInfo.callsFake(function (): KeyStoreInfoOutput {
      return {
        keystoreId: 'keyStoreId',
        keystoreTableName: 'keystoreTableName',
        logicalKeyStoreName: 'logicalKeyStoreName',
        grantTokens: [],
        // This is not used by any tests
        kmsConfiguration: null as any,
      }
    })
  })

  // what to do after each test: reset all sinons
  afterEach(() => {
    keyStore.getActiveBranchKey.reset()
    kmsSendSpy.restore()
    ddbSendSpy.restore()
    clock.restore()
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=test
  //# The `branchKeyId` used in this operation is either the configured branchKeyId, if supplied, or the result of the `branchKeySupplier`'s
  //# `getBranchKeyId` operation, using the encryption material's encryption context as input.
  it('Uses either the branch key id or supplier', async () => {
    let hkr = new KmsHierarchicalKeyRingNode({
      branchKeyIdSupplier,
      keyStore,
      cacheLimitTtl,
    })

    await testOnEncrypt(
      hkr,
      branchKeyIdA,
      new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
    )

    hkr = new KmsHierarchicalKeyRingNode({
      branchKeyId: branchKeyIdA,
      keyStore,
      cacheLimitTtl,
    })

    await testOnEncrypt(
      hkr,
      branchKeyIdA,
      new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
    )
  })

  it('Error in the branch key id supplier leads to operation failure', async () => {
    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyIdSupplier,
      keyStore,
      cacheLimitTtl,
    })

    await testOnEncryptError(
      hkr,
      new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC),
      "Can't determine branchKeyId from context"
    )
  })

  describe('Getting the pdk', () => {
    it('Existing pdk is zeroed', async () => {
      const encryptionMaterial = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )

      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })

      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterial)

      // now zero it out and try
      encryptionMaterial.zeroUnencryptedDataKey()
      await testOnEncryptError(
        hkr,
        encryptionMaterial,
        'unencryptedDataKey has already been set'
      )
    })

    it('Pdk is zeroed without being set', async () => {
      const encryptionMaterial = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      ).zeroUnencryptedDataKey()

      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })

      await testOnEncryptError(
        hkr,
        encryptionMaterial,
        'unencryptedDataKey has already been set'
      )
    })

    it('Existing pdk is not overriden', async () => {
      const encryptionMaterial = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })

      // one call to generate an initial pdk
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterial)

      // another call to ensure the existing pdk does not change
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterial)
    })

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
    //= type=test
    //# If the input [encryption materials](../structures.md#encryption-materials) do not contain a plaintext data key,
    //# OnEncrypt MUST generate a random plaintext data key, according to the key length defined in the [algorithm suite](../algorithm-suites.md#encryption-key-length).
    //# The process used to generate this random plaintext data key MUST use a secure source of randomness.
    it('Correct length pdk is generated for all algorithm suites', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })

      for (const algSuite of ALG_SUITES) {
        // run onEncrypt with an encryption material for each algorithm suite
        await testOnEncrypt(
          hkr,
          branchKeyIdA,
          new NodeEncryptionMaterial(algSuite, DEFAULT_EC)
        )
      }
    })
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=test
  //# If a cache entry is found and the entry's TTL has not expired, the hierarchical keyring MUST use those branch key materials for key wrapping.

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt
  //= type=test
  //# If a cache entry is not found or the cache entry is expired, the hierarchical keyring MUST attempt to obtain the branch key materials
  //# by querying the backing branch keystore specified in the [retrieve OnEncrypt branch key materials](#query-branch-keystore-onencrypt) section.
  //# If the keyring is not able to retrieve [branch key materials](../structures.md#branch-key-materials)
  //# through the underlying cryptographic materials cache or
  //# it no longer has access to them through the backing keystore, OnEncrypt MUST fail.
  describe('Getting the branch key material', () => {
    it('Material X not already in the CMC or keystore, request material X', async () => {
      const branchKeyId = 'lol'
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId,
        keyStore,
        cacheLimitTtl,
      })
      const encryptionMaterial = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )

      // there is nothing in the cmc, so onEncrypt will request active branch key
      // material from keystore. It will try to query DDB for 'lol' and not find
      // an item
      await testOnEncryptError(
        hkr,
        encryptionMaterial,
        `A branch key record with branch-key-id=${branchKeyId} and type=branch:ACTIVE was not found in DynamoDB`
      )
      expect(kmsSendSpy.callCount).equals(0)
      expect(ddbSendSpy.callCount).equals(1)
    })

    it('Material X not already in CMC, request for Material X', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const encryptionMaterial = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )

      // there is nothing in the cmc, so onEncrypt will get active branch key
      // material from the keystore. This makes 1 call to DDB and 1 to KMS
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterial)
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)
    })

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
    //= type=test
    //# OnEncrypt MUST call the Keystore's [GetActiveBranchKey](../branch-key-store.md#getactivebranchkey) operation with the following inputs:
    //# - the `branchKeyId` used in this operation
    
    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#query-branch-keystore-onencrypt
    //= type=test
    //# If the Keystore's GetActiveBranchKey operation succeeds
    //# the keyring MUST put the returned branch key materials in the cache using the
    //# formula defined in [Appendix A](#appendix-a-cache-entry-identifier-formulas).
    it('Material X already in CMC, request for Material X', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const encryptionMaterial = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )

      // in this call, onEncrypt queries the clients to get active branch
      // key material and caches it in the cmc.
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterial)
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)

      // in this call, onEncrypt needs the same active branch key material and they
      // are already in the CMC
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterial)
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)
    })

    it('Material A already in the CMC, ask for material B in keystore', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyIdSupplier,
        keyStore,
        cacheLimitTtl,
      })
      const encryptionMaterialA = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        EC_A
      )
      const encryptionMaterialB = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        EC_B
      )

      // this call will get active branch key material A from the keystore and
      // cache it
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterialA)
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)

      // this call needs active branch key material B. It is not in the keystore
      // so it will make network calls
      await testOnEncrypt(hkr, branchKeyIdB, encryptionMaterialB)
      expect(kmsSendSpy.callCount).equals(2)
      expect(ddbSendSpy.callCount).equals(2)
    })

    it('CMC evictions occur due to long network calls', async () => {
      const cacheLimitTtl = 10 / 1000 // set to 10 ms
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl: cacheLimitTtl,
      })
      const encryptionMaterial = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )

      // active branch key material is not cached, so make network calls and
      // cache it
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterial)
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)

      // stall for twice ttl such that the CMC is fully evicted
      clock.tick(cacheLimitTtl * 2 * 1000)

      // active branch key material is not cached, so make network calls again
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterial)
      expect(kmsSendSpy.callCount).equals(2)
      expect(ddbSendSpy.callCount).equals(2)
    })

    it('CMC evictions occur due to capacity', async () => {
      const maxCacheSize = 1
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyIdSupplier,
        keyStore,
        cacheLimitTtl,
        maxCacheSize,
      })
      const encryptionMaterialA = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        EC_A
      )
      const encryptionMaterialB = new NodeEncryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        EC_B
      )

      // active branch key material A is not cached, so make network calls and
      // cache it
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterialA)
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)

      // active branch key material B is not cached, so make network calls and
      // cache it. This evicts active branch key material A due to capacity
      // being exceeded
      await testOnEncrypt(hkr, branchKeyIdB, encryptionMaterialB)
      expect(kmsSendSpy.callCount).equals(2)
      expect(ddbSendSpy.callCount).equals(2)

      // active branch key material A is not cached, so make network calls and
      // cache it again
      await testOnEncrypt(hkr, branchKeyIdA, encryptionMaterialA)
      expect(kmsSendSpy.callCount).equals(3)
      expect(ddbSendSpy.callCount).equals(3)
    })
  })
})
