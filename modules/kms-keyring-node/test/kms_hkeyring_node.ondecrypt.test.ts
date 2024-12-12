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
import {
  IKmsHierarchicalKeyRingNode,
  KmsHierarchicalKeyRingNode,
} from '../src/kms_hkeyring_node'
import {
  BRANCH_KEY_ID_SUPPLIER,
  deepCopyBranchKeyMaterial,
  testOnDecrypt,
  testOnDecryptError,
  testOnEncrypt,
} from './kms_hkeyring_node.test'
import { expect } from 'chai'
import Sinon from 'sinon'
import { KMSClient } from '@aws-sdk/client-kms'
import { DynamoDBClient } from '@aws-sdk/client-dynamodb'
import { BranchKeyStoreNode, KeyStoreInfoOutput } from '@aws-crypto/branch-keystore-node'

const branchKeyIdA = BRANCH_KEY_ID_A
const branchKeyIdB = BRANCH_KEY_ID_B
const branchKeyIdSupplier = BRANCH_KEY_ID_SUPPLIER
const originalKeyStore = KEYSTORE
const cacheLimitTtl = TTL

async function generatePdkAndEdks(
  hkr: IKmsHierarchicalKeyRingNode,
  wrappingKeyName: string,
  encryptionMaterial: NodeEncryptionMaterial
) {
  await testOnEncrypt(hkr, wrappingKeyName, encryptionMaterial)

  const encryptedPdk = unwrapDataKey(encryptionMaterial.getUnencryptedDataKey())
  const edks = encryptionMaterial.encryptedDataKeys

  return { encryptedPdk, edks }
}

let versionedBranchKeyMaterialA: NodeBranchKeyMaterial
let versionedBranchKeyMaterialB: NodeBranchKeyMaterial
let activeVersionA: string
let activeVersionB: string
let activeBranchKeyMaterialA: NodeBranchKeyMaterial
let activeBranchKeyMaterialB: NodeBranchKeyMaterial
before(async function () {
  activeBranchKeyMaterialA = await originalKeyStore.getActiveBranchKey(
    branchKeyIdA
  )
  activeVersionA = activeBranchKeyMaterialA.branchKeyVersion.toString('utf-8')

  activeBranchKeyMaterialB = await originalKeyStore.getActiveBranchKey(
    branchKeyIdB
  )
  activeVersionB = activeBranchKeyMaterialB.branchKeyVersion.toString('utf-8')

  versionedBranchKeyMaterialA = await originalKeyStore.getBranchKeyVersion(
    branchKeyIdA,
    activeVersionA
  )

  versionedBranchKeyMaterialB = await originalKeyStore.getBranchKeyVersion(
    branchKeyIdB,
    activeVersionB
  )
})

describe('KmsHierarchicalKeyRingNode: onDecrypt', () => {
  let keyStore: Sinon.SinonStubbedInstance<BranchKeyStoreNode>
  let kmsSendSpy: Sinon.SinonSpy
  let ddbSendSpy: Sinon.SinonSpy
  let clock: Sinon.SinonFakeTimers

  beforeEach(() => {
    keyStore = Sinon.createStubInstance(BranchKeyStoreNode)
    kmsSendSpy = Sinon.spy(KMSClient.prototype, 'send')
    ddbSendSpy = Sinon.spy(DynamoDBClient.prototype, 'send')
    clock = Sinon.useFakeTimers()

    keyStore.getActiveBranchKey.callsFake(async function (branchKeyId: string) {
      if (branchKeyId === branchKeyIdA) {
        return deepCopyBranchKeyMaterial(activeBranchKeyMaterialA)
      } else if (branchKeyId === branchKeyIdB) {
        return deepCopyBranchKeyMaterial(activeBranchKeyMaterialB)
      } else {
        throw new Error(
          `A branch key record with branch-key-id=${branchKeyId} and type=branch:ACTIVE was not found in DynamoDB`
        )
      }
    })

    keyStore.getBranchKeyVersion.callsFake(async function (
      branchKeyId: string,
      branchKeyVersion: string
    ) {
      if (branchKeyId === branchKeyIdA && branchKeyVersion === activeVersionA) {
        kmsSendSpy.callCount += 1
        ddbSendSpy.callCount += 1
        return deepCopyBranchKeyMaterial(versionedBranchKeyMaterialA)
      } else if (
        branchKeyId === branchKeyIdB &&
        branchKeyVersion === activeVersionB
      ) {
        kmsSendSpy.callCount += 1
        ddbSendSpy.callCount += 1
        return deepCopyBranchKeyMaterial(versionedBranchKeyMaterialB)
      } else {
        ddbSendSpy.callCount += 1
        throw new Error(
          `A branch key record with branch-key-id=${branchKeyId} and type=branch:version:${branchKeyVersion} was not found in DynamoDB`
        )
      }
    })

    keyStore.getKeyStoreInfo.callsFake(function(): KeyStoreInfoOutput {
      return {
        keystoreId: "keyStoreId",
        keystoreTableName: "keystoreTableName",
        logicalKeyStoreName: "logicalKeyStoreName",
        grantTokens: [],
        // This is not used by any tests
        kmsConfiguration: null as any
      }
    })
  })

  afterEach(() => {
    keyStore.getActiveBranchKey.reset()
    keyStore.getBranchKeyVersion.reset()
    kmsSendSpy.restore()
    ddbSendSpy.restore()
    clock.restore()
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
  //= type=test
  //# The `branchKeyId` used in this operation is either the configured branchKeyId, if supplied, or the result of the `branchKeySupplier`'s
  //# `getBranchKeyId` operation, using the decryption material's encryption context as input.
  it('Uses either the branch key id or supplier', async () => {
    let hkr = new KmsHierarchicalKeyRingNode({
      branchKeyIdSupplier,
      keyStore,
      cacheLimitTtl,
    })
    let { encryptedPdk, edks } = await generatePdkAndEdks(
      hkr,
      branchKeyIdA,
      new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
    )

    await testOnDecrypt(
      hkr,
      encryptedPdk,
      edks,
      branchKeyIdA,
      new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
    )

    hkr = new KmsHierarchicalKeyRingNode({
      branchKeyId: branchKeyIdA,
      keyStore,
      cacheLimitTtl,
    })

    const result = await generatePdkAndEdks(
      hkr,
      branchKeyIdA,
      new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
    )
    encryptedPdk = result.encryptedPdk
    edks = result.edks

    await testOnDecrypt(
      hkr,
      encryptedPdk,
      edks,
      branchKeyIdA,
      new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
    )
  })

  it('Error in the branch key id supplier leads to operation failure', async () => {
    const hkr = new KmsHierarchicalKeyRingNode({
      branchKeyIdSupplier,
      keyStore,
      cacheLimitTtl,
    })
    const decryptionMaterial = new NodeDecryptionMaterial(
      TEST_ESDK_ALG_SUITE,
      DEFAULT_EC
    )
    const { edks } = await generatePdkAndEdks(
      hkr,
      branchKeyIdA,
      new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
    )

    await testOnDecryptError(
      hkr,
      edks,
      decryptionMaterial,
      "Can't determine branchKeyId from context"
    )
  })

  describe('Setting the pdk after edk decryption', () => {
    it('Decryption material has a pdk that is set and later zeroed out', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const decryptionMaterial = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )
      const { encryptedPdk, edks } = await generatePdkAndEdks(
        hkr,
        branchKeyIdA,
        new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )

      // this first decryption will set the pdk
      await testOnDecrypt(
        hkr,
        encryptedPdk,
        edks,
        branchKeyIdA,
        decryptionMaterial
      )

      // then we zero out the pdk, rendering the decryption material dead
      decryptionMaterial.zeroUnencryptedDataKey()

      // then we should fail to decrypt the edks this time
      await testOnDecryptError(
        hkr,
        edks,
        decryptionMaterial,
        'unencryptedDataKey has already been set'
      )
    })

    it('Decryption material has a pdk that is not set and immediately zeroed out', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const decryptionMaterial = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      ).zeroUnencryptedDataKey()
      const { edks } = await generatePdkAndEdks(
        hkr,
        branchKeyIdA,
        new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )

      await testOnDecryptError(
        hkr,
        edks,
        decryptionMaterial,
        'unencryptedDataKey has already been set'
      )
    })

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
    //= type=test
    //# If the decryption materials already contain a `PlainTextDataKey`, OnDecrypt MUST fail.
    it('Precondition: If the decryption materials already contain a PlainTextDataKey, OnDecrypt MUST fail', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const decryptionMaterial = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )
      const { encryptedPdk, edks } = await generatePdkAndEdks(
        hkr,
        branchKeyIdA,
        new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )

      // this first decryption will set the pdk
      await testOnDecrypt(
        hkr,
        encryptedPdk,
        edks,
        branchKeyIdA,
        decryptionMaterial
      )

      // then we should fail to decrypt the edks this time
      await testOnDecryptError(
        hkr,
        edks,
        decryptionMaterial,
        'Decryption materials already contain a plaintext data key'
      )
    })

    it('Correct length pdk is decrypted for all algorithm suites', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })

      for (const algSuite of ALG_SUITES) {
        const { encryptedPdk, edks } = await generatePdkAndEdks(
          hkr,
          branchKeyIdA,
          new NodeEncryptionMaterial(algSuite, DEFAULT_EC)
        )

        await testOnDecrypt(
          hkr,
          encryptedPdk,
          edks,
          branchKeyIdA,
          new NodeDecryptionMaterial(algSuite, DEFAULT_EC)
        )
      }
    })
  })

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
  //= type=test
  //# If a cache entry is found and the entry's TTL has not expired, the hierarchical keyring MUST use those branch key materials for key unwrapping.

  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt
  //# If a cache entry is not found or the cache entry is expired, the hierarchical keyring
  //# MUST attempt to obtain the branch key materials by calling the backing branch key
  //# store specified in the [retrieve OnDecrypt branch key materials](#getitem-branch-keystore-ondecrypt) section.
  //# If the keyring is not able to retrieve `branch key materials` from the backing keystore then OnDecrypt MUST fail.
  describe('Getting the branch key material', () => {
    it('Material X not already in the CMC or keystore, request material X', async () => {
      let hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const { edks } = await generatePdkAndEdks(
        hkr,
        branchKeyIdA,
        new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )

      // modify the edks such that their wrapping key name is not the existent
      // branch key id that they were originally wrapped with
      const nonexistentBranchKeyId = 'lol'
      const modifiedEdks = edks.map(
        (edk) =>
          new EncryptedDataKey({
            ...edk,
            providerInfo: nonexistentBranchKeyId,
          })
      )

      hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: nonexistentBranchKeyId, // so that the edks match the keyring configuration and pass the filter
        keyStore,
        cacheLimitTtl,
      })

      const decyrptionMaterial = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )

      // now when we try to decrypt, we will get an error saying that we
      // couldn't get the necessary versioned branch key material to unwrap the
      // edk
      await testOnDecryptError(
        hkr,
        modifiedEdks,
        decyrptionMaterial,
        undefined,
        [
          `A branch key record with branch-key-id=${nonexistentBranchKeyId} and type=branch:version:${activeVersionA} was not found in DynamoDB`,
        ]
      )

      expect(ddbSendSpy.callCount).equals(1)
      expect(kmsSendSpy.callCount).equals(0)
    })

    it('Material X not already in CMC, request for Material X', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const decryptionMaterial = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )
      const { encryptedPdk, edks } = await generatePdkAndEdks(
        hkr,
        branchKeyIdA,
        new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )

      // the versioned branch key material that we want is not in the CMC, so we
      // get it from the keystore
      await testOnDecrypt(
        hkr,
        encryptedPdk,
        edks,
        branchKeyIdA,
        decryptionMaterial
      )
      expect(ddbSendSpy.callCount).equals(1)
      expect(kmsSendSpy.callCount).equals(1)
    })

    //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#getitem-branch-keystore-ondecrypt
    //= type=test
    //# The branch keystore persists [branch keys](#definitions) that are reused to derive unique data keys for key wrapping to
    //# reduce the number of calls to AWS KMS through the use of the
    //# [cryptographic materials cache](../cryptographic-materials-cache.md).
    //# OnDecrypt MUST calculate the following values:
    //# - Deserialize the UTF8-Decoded `branch-key-id` from the [key provider info](../structures.md#key-provider-information) of the [encrypted data key](../structures.md#encrypted-data-key)
    //#   and verify this is equal to the configured or supplied `branch-key-id`.
    //# - Deserialize the UUID string representation of the `version` from the [encrypted data key](../structures.md#encrypted-data-key) [ciphertext](#ciphertext).
    //# OnDecrypt MUST call the Keystore's [GetBranchKeyVersion](../branch-key-store.md#getbranchkeyversion) operation with the following inputs:
    //# - The deserialized, UTF8-Decoded `branch-key-id`
    //# - The deserialized UUID string representation of the `version`
    //# If the Keystore's GetBranchKeyVersion operation succeeds
    //# the keyring MUST put the returned branch key materials in the cache using the
    //# formula defined in [Appendix A](#appendix-a-cache-entry-identifier-formulas).
    //# Otherwise, OnDecrypt MUST fail.
    it('Material X already in CMC, request for Material X', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const decyrptionMaterial = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        DEFAULT_EC
      )
      const { encryptedPdk, edks } = await generatePdkAndEdks(
        hkr,
        branchKeyIdA,
        new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )

      await testOnDecrypt(
        hkr,
        encryptedPdk,
        edks,
        branchKeyIdA,
        new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)

      // the versioned branch key material that we want is already in the CMC,
      // so we don't need to call the keystore
      await testOnDecrypt(
        hkr,
        encryptedPdk,
        edks,
        branchKeyIdA,
        decyrptionMaterial
      )

      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)
    })

    it('Material A already in the CMC, ask for material B in keystore', async () => {
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyIdSupplier,
        keyStore,
        cacheLimitTtl,
      })
      // create decryption materials to tell onDecrypt to attempt decrypting the
      // edks by unwrapping with branch key A
      const decryptionMaterialA = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        EC_A
      )
      // create decryption materials to tell onDecrypt to attempt decrypting the
      // edks by unwrapping with branch key A
      const decryptionMaterialB = new NodeDecryptionMaterial(
        TEST_ESDK_ALG_SUITE,
        EC_B
      )

      const { encryptedPdk: encryptedPdkA, edks: edksA } =
        await generatePdkAndEdks(
          hkr,
          branchKeyIdA,
          new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
        )
      const { encryptedPdk: encryptedPdkB, edks: edksB } =
        await generatePdkAndEdks(
          hkr,
          branchKeyIdB,
          new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_B)
        )

      // use branch key A to decrypt the edks that were wrapped with branch key
      // A. This calls the keystore to get the versioned branch key material A,
      // and puts it into the CMC
      await testOnDecrypt(
        hkr,
        encryptedPdkA,
        edksA,
        branchKeyIdA,
        decryptionMaterialA
      )
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)

      // use branch key B to decrypt the edks that were wrapped with branch key
      // B. This calls the keystore to get the versioned branch key material B
      // because it is not in the CMC. Only versioned branch key material A is
      // in the CMC
      await testOnDecrypt(
        hkr,
        encryptedPdkB,
        edksB,
        branchKeyIdB,
        decryptionMaterialB
      )
      expect(kmsSendSpy.callCount).equals(2)
      expect(ddbSendSpy.callCount).equals(2)
    })

    it('CMC evictions occur due to long network calls', async () => {
      const cacheLimitTtl = 10 / 1000 // set to 10 ms
      const hkr = new KmsHierarchicalKeyRingNode({
        branchKeyId: branchKeyIdA,
        keyStore,
        cacheLimitTtl,
      })
      const { encryptedPdk, edks } = await generatePdkAndEdks(
        hkr,
        branchKeyIdA,
        new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )

      // To decrypt the edks, we need to get branch key material from the
      // keystore
      await testOnDecrypt(
        hkr,
        encryptedPdk,
        edks,
        branchKeyIdA,
        new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)

      // stall for twice TTL such that we evict the branch key material that we just put in the cmc
      // from the previous decrypt call
      clock.tick(cacheLimitTtl * 2 * 1000)

      // now we attempt to decrypt using the same branch key material again.
      // However, it is not in the CMC so we must call the keystore again
      await testOnDecrypt(
        hkr,
        encryptedPdk,
        edks,
        branchKeyIdA,
        new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, DEFAULT_EC)
      )
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

      const { encryptedPdk: encryptedPdkA, edks: edksA } =
        await generatePdkAndEdks(
          hkr,
          branchKeyIdA,
          new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
        )
      const { encryptedPdk: encryptedPdkB, edks: edksB } =
        await generatePdkAndEdks(
          hkr,
          branchKeyIdB,
          new NodeEncryptionMaterial(TEST_ESDK_ALG_SUITE, EC_B)
        )

      // decrypt edks A using branch key material A. Branch key material A is
      // not in the cmc yet so we call the keystore
      await testOnDecrypt(
        hkr,
        encryptedPdkA,
        edksA,
        branchKeyIdA,
        new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
      )
      expect(kmsSendSpy.callCount).equals(1)
      expect(ddbSendSpy.callCount).equals(1)

      // decrypt edks B using branch key material B. Branch key material B is
      // not in the cmc yet so we call the keystore. Since the cmc capacity is
      // 1, this evicts the branch key material A that we just put into the cmc
      // during the previous decrypt call
      await testOnDecrypt(
        hkr,
        encryptedPdkB,
        edksB,
        branchKeyIdB,
        new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, EC_B)
      )
      expect(kmsSendSpy.callCount).equals(2)
      expect(ddbSendSpy.callCount).equals(2)

      // now we want to decrypt under branch key material A again, but it is not
      // in the cmc. So we must call the keystore
      await testOnDecrypt(
        hkr,
        encryptedPdkA,
        edksA,
        branchKeyIdA,
        new NodeDecryptionMaterial(TEST_ESDK_ALG_SUITE, EC_A)
      )
      expect(kmsSendSpy.callCount).equals(3)
      expect(ddbSendSpy.callCount).equals(3)
    })
  })
})
