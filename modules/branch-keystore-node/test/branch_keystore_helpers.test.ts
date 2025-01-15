// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import chai, { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { BranchKeyStoreNode } from '../src/branch_keystore'
import {
  constructAuthenticatedEncryptionContext,
  constructBranchKeyMaterials,
  decryptBranchKey,
  getBranchKeyItem,
  validateBranchKeyRecord,
} from '../src/branch_keystore_helpers'
import { KMSClient } from '@aws-sdk/client-kms'
import { getRegionFromIdentifier } from '@aws-crypto/kms-keyring'
import { DecryptCommand } from '@aws-sdk/client-kms'
import {
  BRANCH_KEY_ID,
  DDB_TABLE_NAME,
  KEY_ARN,
  LOGICAL_KEYSTORE_NAME,
  ACTIVE_BRANCH_KEY,
  VERSION_BRANCH_KEY,
  ENCRYPTED_ACTIVE_BRANCH_KEY,
  ENCRYPTED_VERSION_BRANCH_KEY,
} from './fixtures'
import { BranchKeyItem } from '../src/branch_keystore_structures'
import {
  BRANCH_KEY_ACTIVE_TYPE,
  BRANCH_KEY_ACTIVE_VERSION_FIELD,
  BRANCH_KEY_FIELD,
  BRANCH_KEY_IDENTIFIER_FIELD,
  BRANCH_KEY_TYPE_PREFIX,
  HIERARCHY_VERSION_FIELD,
  KEY_CREATE_TIME_FIELD,
  KMS_FIELD,
  TYPE_FIELD,
  PARTITION_KEY,
  SORT_KEY,
} from '../src/constants'
import { DynamoDBKeyStorage } from '../src/dynamodb_key_storage'
import { EncryptedHierarchicalKey } from '../src/types'

const VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS = {
  'aws-crypto-ec:key1': 'value 1',
  'aws-crypto-ec:key2': 2,
  'aws-crypto-ec:key3': true,
}

const VALID_CUSTOM_ENCRYPTION_CONTEXT = Object.fromEntries(
  Object.entries({ ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS }).map(
    ([key, value]) => [key, value.toString()]
  )
)

const INVALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS = {
  'awz-crypto-ec:key1': 'value 1',
  key2: 'value 2',
  'aws-crypt0-ec:key3': 'value 3',
}

const BRANCH_KEYSTORE = new BranchKeyStoreNode({
  storage: { ddbTableName: DDB_TABLE_NAME },
  logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
  kmsConfiguration: { identifier: KEY_ARN },
})

const BRANCH_KEY_STORAGE = BRANCH_KEYSTORE.storage as DynamoDBKeyStorage

chai.use(chaiAsPromised)
// TODO: Should we mock DDB and KMS client?
describe('Test keystore helpers', () => {
  describe('Test getBranchKeyItem', () => {
    it('Getting an active branch key', async () => {
      const item = await getBranchKeyItem(
        BRANCH_KEY_STORAGE,
        BRANCH_KEY_ID,
        BRANCH_KEY_ACTIVE_TYPE
      )

      expect(
        item &&
          TYPE_FIELD in item &&
          item[TYPE_FIELD] == BRANCH_KEY_ACTIVE_TYPE &&
          BRANCH_KEY_ACTIVE_VERSION_FIELD in item &&
          item[BRANCH_KEY_ACTIVE_VERSION_FIELD].startsWith(
            BRANCH_KEY_TYPE_PREFIX
          )
      ).equals(true)
    })

    it('Getting a versioned branch key', async () => {
      const item = await getBranchKeyItem(
        BRANCH_KEY_STORAGE,
        BRANCH_KEY_ID,
        ENCRYPTED_VERSION_BRANCH_KEY.encryptionContext[TYPE_FIELD]
      )

      expect(
        item &&
          !(BRANCH_KEY_ACTIVE_VERSION_FIELD in item) &&
          item[TYPE_FIELD].startsWith(BRANCH_KEY_TYPE_PREFIX)
      ).equals(true)
    })

    it('Getting an active & versioned branch key via a nonexistent branch key id', async () => {
      const nonexistentBranchKeyId = BRANCH_KEY_ID.replace('8', '7')

      void (await expect(
        getBranchKeyItem(
          BRANCH_KEY_STORAGE,
          nonexistentBranchKeyId,
          BRANCH_KEY_ACTIVE_TYPE
        )
      ).to.rejectedWith(
        `A branch key record with ${PARTITION_KEY}=${nonexistentBranchKeyId} and ${SORT_KEY}=${BRANCH_KEY_ACTIVE_TYPE} was not found in the DynamoDB table ${DDB_TABLE_NAME}.`
      ))

      void (await expect(
        getBranchKeyItem(
          BRANCH_KEY_STORAGE,
          nonexistentBranchKeyId,
          VERSION_BRANCH_KEY[TYPE_FIELD]
        )
      ).to.be.rejectedWith(
        `A branch key record with ${PARTITION_KEY}=${nonexistentBranchKeyId} and ${SORT_KEY}=${VERSION_BRANCH_KEY[TYPE_FIELD]} was not found in the DynamoDB table ${DDB_TABLE_NAME}.`
      ))
    })

    it('Getting a versioned branch key via a nonexistent version', async () => {
      const type = VERSION_BRANCH_KEY[TYPE_FIELD]
      const nonexistentType = type.replace('0', '1')

      void (await expect(
        getBranchKeyItem(BRANCH_KEY_STORAGE, BRANCH_KEY_ID, nonexistentType)
      ).to.be.rejectedWith(
        `A branch key record with ${PARTITION_KEY}=${BRANCH_KEY_ID} and ${SORT_KEY}=${nonexistentType} was not found in the DynamoDB table ${DDB_TABLE_NAME}.`
      ))
    })
  })

  describe('Test validateBranchKeyRecord', () => {
    it('With valid active & versioned branch key items', () => {
      expect(validateBranchKeyRecord(ACTIVE_BRANCH_KEY)).to.deep.equals(
        ACTIVE_BRANCH_KEY
      )
      expect(validateBranchKeyRecord(VERSION_BRANCH_KEY)).to.deep.equals(
        VERSION_BRANCH_KEY
      )
    })

    it('With valid active & versioned items bearing extra keys prefixed properly', () => {
      const activeItem = {
        ...ACTIVE_BRANCH_KEY,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      }
      expect(validateBranchKeyRecord(activeItem)).to.deep.equals({
        ...ACTIVE_BRANCH_KEY,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      })

      const versionItem = {
        ...VERSION_BRANCH_KEY,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      }
      expect(validateBranchKeyRecord(versionItem)).to.deep.equals({
        ...VERSION_BRANCH_KEY,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      })
    })

    // = aws-encryption-sdk-specification/framework/branch-key-store.md#record-format
    // = type=test
    // # 1. `branch-key-id` : Unique identifier for a branch key; represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
    it(`Active & versioned items have no ${BRANCH_KEY_IDENTIFIER_FIELD} field`, () => {
      const activeItem: BranchKeyItem = { ...ACTIVE_BRANCH_KEY }
      delete activeItem[BRANCH_KEY_IDENTIFIER_FIELD]
      expect(() => validateBranchKeyRecord(activeItem)).to.throw(
        `Branch keystore record does not contain a ${BRANCH_KEY_IDENTIFIER_FIELD} field of type string`
      )

      const versionedItem: BranchKeyItem = { ...VERSION_BRANCH_KEY }
      delete versionedItem[BRANCH_KEY_IDENTIFIER_FIELD]
      expect(() => validateBranchKeyRecord(versionedItem)).to.throw(
        `Branch keystore record does not contain a ${BRANCH_KEY_IDENTIFIER_FIELD} field of type string`
      )
    })

    // = aws-encryption-sdk-specification/framework/branch-key-store.md#record-format
    // = type=test
    // # 1. `type` : One of the following; represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
    // #   - The string literal `"beacon:ACTIVE"`. Then `enc` is the wrapped beacon key.
    // #   - The string `"branch:version:"` + `version`, where `version` is the Branch Key Version. Then `enc` is the wrapped branch key.
    // #   - The string literal `"branch:ACTIVE"`. Then `enc` is the wrapped beacon key of the active version.
    it(`Active & versioned items have no ${TYPE_FIELD} field`, () => {
      const activeItem: BranchKeyItem = { ...ACTIVE_BRANCH_KEY }
      delete activeItem[TYPE_FIELD]
      expect(() => validateBranchKeyRecord(activeItem)).to.throw(
        `Branch keystore record does not contain a valid ${TYPE_FIELD} field of type string`
      )

      const versionedItem: BranchKeyItem = { ...VERSION_BRANCH_KEY }
      delete versionedItem[TYPE_FIELD]
      expect(() => validateBranchKeyRecord(versionedItem)).to.throw(
        `Branch keystore record does not contain a valid ${TYPE_FIELD} field of type string`
      )
    })

    it(`Versioned branch key item has an improper ${TYPE_FIELD} field`, () => {
      const item = { ...VERSION_BRANCH_KEY }
      item[TYPE_FIELD] = item[TYPE_FIELD].substring(
        BRANCH_KEY_TYPE_PREFIX.length
      )
      expect(() => validateBranchKeyRecord(item)).to.throw(
        `Branch keystore record does not contain a valid ${TYPE_FIELD} field of type string`
      )
    })

    it('Item type is none of 3 possible types (branch:ACTIVE, starting with branch:version:, or beacon:ACTIVE)', () => {
      const item = { ...ACTIVE_BRANCH_KEY }
      item[TYPE_FIELD] = 'lol'
      expect(() => validateBranchKeyRecord(item)).to.throw(
        `Branch keystore record does not contain a valid ${TYPE_FIELD} field of type string`
      )
    })

    // = aws-encryption-sdk-specification/framework/branch-key-store.md#record-format
    // = type=test
    // # 1. `version` : Only exists if `type` is the string literal `"branch:ACTIVE"`.
    // #   Then it is the Branch Key Version. represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
    it(`Active branch key item has no ${BRANCH_KEY_ACTIVE_VERSION_FIELD} field`, () => {
      const item: BranchKeyItem = { ...ACTIVE_BRANCH_KEY }
      delete item[BRANCH_KEY_ACTIVE_VERSION_FIELD]
      expect(() => validateBranchKeyRecord(item)).to.throw(
        `Branch keystore record does not contain a ${BRANCH_KEY_ACTIVE_VERSION_FIELD} field of type string`
      )
    })

    // = aws-encryption-sdk-specification/framework/branch-key-store.md#record-format
    // = type=test
    // # 1. `enc` : Encrypted version of the key;
    // #   represented as [AWS DDB Binary](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
    it(`Active & versioned items have no ${BRANCH_KEY_FIELD} field`, () => {
      const activeItem: BranchKeyItem = { ...ACTIVE_BRANCH_KEY }
      delete activeItem[BRANCH_KEY_FIELD]
      expect(() => validateBranchKeyRecord(activeItem)).to.throw(
        `Branch keystore record does not contain ${BRANCH_KEY_FIELD} field of type Uint8Array`
      )

      const versionedItem: BranchKeyItem = { ...VERSION_BRANCH_KEY }
      delete versionedItem[BRANCH_KEY_FIELD]
      expect(() => validateBranchKeyRecord(versionedItem)).to.throw(
        `Branch keystore record does not contain ${BRANCH_KEY_FIELD} field of type Uint8Array`
      )
    })

    // = aws-encryption-sdk-specification/framework/branch-key-store.md#record-format
    // = type=test
    // # 1. `kms-arn`: The AWS KMS Key ARN used to generate the `enc` value.
    // #   represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
    it(`Active & versioned items have no ${KMS_FIELD} field`, () => {
      const activeItem: BranchKeyItem = { ...ACTIVE_BRANCH_KEY }
      delete activeItem[KMS_FIELD]
      expect(() => validateBranchKeyRecord(activeItem)).to.throw(
        `Branch keystore record does not contain ${KMS_FIELD} field of type string`
      )

      const versionedItem: BranchKeyItem = { ...VERSION_BRANCH_KEY }
      delete versionedItem[KMS_FIELD]
      expect(() => validateBranchKeyRecord(versionedItem)).to.throw(
        `Branch keystore record does not contain ${KMS_FIELD} field of type string`
      )
    })

    // = aws-encryption-sdk-specification/framework/branch-key-store.md#record-format
    // = type=test
    // # 1. `create-time`: Timestamp in ISO 8601 format in UTC, to microsecond precision.
    // #   Represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
    it(`Active & versioned items have no ${KEY_CREATE_TIME_FIELD} field`, () => {
      const activeItem: BranchKeyItem = { ...ACTIVE_BRANCH_KEY }
      delete activeItem[KEY_CREATE_TIME_FIELD]
      expect(() => validateBranchKeyRecord(activeItem)).to.throw(
        `Branch keystore record does not contain ${KEY_CREATE_TIME_FIELD} field of type string`
      )

      const versionedItem: BranchKeyItem = { ...VERSION_BRANCH_KEY }
      delete versionedItem[KEY_CREATE_TIME_FIELD]
      expect(() => validateBranchKeyRecord(versionedItem)).to.throw(
        `Branch keystore record does not contain ${KEY_CREATE_TIME_FIELD} field of type string`
      )
    })

    // = aws-encryption-sdk-specification/framework/branch-key-store.md#record-format
    // = type=test
    // # 1. `hierarchy-version`: Version of the hierarchical keyring;
    // #   represented as [AWS DDB Number](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
    it(`Active & versioned items have no ${HIERARCHY_VERSION_FIELD} field`, () => {
      const activeItem: BranchKeyItem = { ...ACTIVE_BRANCH_KEY }
      delete activeItem[HIERARCHY_VERSION_FIELD]
      expect(() => validateBranchKeyRecord(activeItem)).to.throw(
        `Branch keystore record does not contain ${HIERARCHY_VERSION_FIELD} field of type number`
      )

      const versionedItem: BranchKeyItem = { ...VERSION_BRANCH_KEY }
      delete versionedItem[HIERARCHY_VERSION_FIELD]
      expect(() => validateBranchKeyRecord(versionedItem)).to.throw(
        `Branch keystore record does not contain ${HIERARCHY_VERSION_FIELD} field of type number`
      )
    })

    // = aws-encryption-sdk-specification/framework/branch-key-store.md#record-format
    // = type=test
    // # A branch key record MAY include [custom encryption context](#custom-encryption-context) key-value pairs.
    // # These attributes should be prefixed with `aws-crypto-ec:` the same way they are for [AWS KMS encryption context](#encryption-context).
    it('Active & versioned items have additional fields prefixed properly', () => {
      const activeItem = {
        ...ACTIVE_BRANCH_KEY,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      }
      expect(validateBranchKeyRecord(activeItem)).deep.equals({
        ...ACTIVE_BRANCH_KEY,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      })

      const versionedItem = {
        ...VERSION_BRANCH_KEY,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      }
      expect(validateBranchKeyRecord(versionedItem)).deep.equals({
        ...VERSION_BRANCH_KEY,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      })
    })

    it('Active & versioned items may have additional fields that are not prefixed', () => {
      const activeItem = {
        ...ACTIVE_BRANCH_KEY,
        ...INVALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      }
      expect(() => validateBranchKeyRecord(activeItem)).to.not.throw()

      const versionedItem = {
        ...VERSION_BRANCH_KEY,
        ...INVALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
      }
      expect(() => validateBranchKeyRecord(versionedItem)).to.not.throw()
    })
  })

  // = aws-encryption-sdk-specification/framework/branch-key-store.md#encryption-context
  // = type=test
  // # This section describes how the AWS KMS encryption context is built
  // # from the DynamoDB items that store the branch keys.
  // # The following encryption context keys are shared:
  // # - MUST have a `branch-key-id` attribute
  // # - The `branch-key-id` field MUST not be an empty string
  // # - MUST have a `type` attribute
  // # - The `type` field MUST not be an empty string
  // # - MUST have a `create-time` attribute
  // # - MUST have a `tablename` attribute to store the logicalKeyStoreName
  // # - MUST have a `kms-arn` attribute
  // # - MUST have a `hierarchy-version`
  // # - MUST NOT have a `enc` attribute
  // # Any additionally attributes on the DynamoDB item
  // # MUST be added to the encryption context.
  describe('Test constructAuthenticatedEncryptionContext', () => {
    it('Given active & versioned branch key records with no custom EC', () => {
      const activeAuthEc = constructAuthenticatedEncryptionContext(
        BRANCH_KEYSTORE,
        ACTIVE_BRANCH_KEY
      )
      expect(activeAuthEc).to.deep.equals(
        ENCRYPTED_ACTIVE_BRANCH_KEY.encryptionContext
      )

      const versionedAuthEc = constructAuthenticatedEncryptionContext(
        BRANCH_KEYSTORE,
        VERSION_BRANCH_KEY
      )
      expect(versionedAuthEc).to.deep.equals(
        ENCRYPTED_VERSION_BRANCH_KEY.encryptionContext
      )
    })

    it('Given active & versioned branch key records with a custom EC', () => {
      const activeAuthEc = constructAuthenticatedEncryptionContext(
        BRANCH_KEYSTORE,
        {
          ...ACTIVE_BRANCH_KEY,
          ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
        }
      )
      expect(activeAuthEc).to.deep.equals({
        ...ENCRYPTED_ACTIVE_BRANCH_KEY.encryptionContext,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT,
      })

      const versionedAuthEc = constructAuthenticatedEncryptionContext(
        BRANCH_KEYSTORE,
        {
          ...VERSION_BRANCH_KEY,
          ...VALID_CUSTOM_ENCRYPTION_CONTEXT_KV_PAIRS,
        }
      )
      expect(versionedAuthEc).to.deep.equals({
        ...ENCRYPTED_VERSION_BRANCH_KEY.encryptionContext,
        ...VALID_CUSTOM_ENCRYPTION_CONTEXT,
      })
    })
  })

  describe('Test decryptBranchKey', () => {
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //= type=test
    //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `KMS Key ARN` or `KMS MRKey ARN`,
    //# the `kms-arn` field of the DDB response item MUST be
    //# [compatible with](#aws-key-arn-compatibility) the configured KMS Key in
    //# the [AWS KMS Configuration](#aws-kms-configuration) for this keystore,
    //# or the operation MUST fail.
    //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `Discovery` or `MRDiscovery`,
    //# the `kms-arn` field of DDB response item MUST NOT be an Alias
    //# or the operation MUST fail.
    it("Active & versioned DDB records' kms-arn's are compatible with KMS config's", async () => {
      const configArn = KEY_ARN

      // create a real up-to-date active branch key record
      const activeEncryptedBranchKey =
        await BRANCH_KEY_STORAGE.getEncryptedActiveBranchKey(BRANCH_KEY_ID)

      const activeBranchKey = await decryptBranchKey(
        BRANCH_KEYSTORE,
        activeEncryptedBranchKey
      )

      const versionedBranchKey = await decryptBranchKey(
        BRANCH_KEYSTORE,
        activeEncryptedBranchKey
      )

      const kmsClient = new KMSClient({
        region: getRegionFromIdentifier(configArn),
      })

      let response = await kmsClient.send(
        new DecryptCommand({
          KeyId: configArn,
          CiphertextBlob: activeEncryptedBranchKey.ciphertextBlob,
          EncryptionContext: activeEncryptedBranchKey.encryptionContext,
        })
      )
      const expectedActiveBranchKey = Buffer.from(
        response.Plaintext as Uint8Array
      )

      // = aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
      // = type=test
      // # When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html),
      // # the keystore operation MUST call with a request constructed as follows:
      // # - `KeyId`, if the KMS Configuration is Discovery, MUST be the `kms-arn` attribute value of the AWS DDB response item.
      // #   If the KMS Configuration is MRDiscovery, `KeyId` MUST be the `kms-arn` attribute value of the AWS DDB response item, with the region replaced by the configured region.
      // #   Otherwise, it MUST BE the Keystore's configured KMS Key.
      // # - `CiphertextBlob` MUST be the `enc` attribute value on the AWS DDB response item
      // # - `EncryptionContext` MUST be the [encryption context](#encryption-context) constructed above
      // # - `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
      response = await kmsClient.send(
        new DecryptCommand({
          KeyId: configArn,
          CiphertextBlob: VERSION_BRANCH_KEY[BRANCH_KEY_FIELD],
          EncryptionContext: ENCRYPTED_VERSION_BRANCH_KEY.encryptionContext,
        })
      )
      const expectedVersionedBranchKey = Buffer.from(
        response.Plaintext as Uint8Array
      )

      expect(activeBranchKey).to.deep.equals(expectedActiveBranchKey)
      expect(versionedBranchKey).to.deep.equals(expectedVersionedBranchKey)
    })

    it("Active & versioned DDB records' kms-arn's are incompatible with KMS config's", async () => {
      const configArn = KEY_ARN.replace('0', '1')
      const branchKeyStore = new BranchKeyStoreNode({
        storage: { ddbTableName: DDB_TABLE_NAME },
        logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
        kmsConfiguration: { identifier: configArn },
      })

      // create a real up-to-date active branch key record
      const activeBranchKeyRecord =
        await branchKeyStore.storage.getEncryptedActiveBranchKey(BRANCH_KEY_ID)

      void (await expect(
        decryptBranchKey(branchKeyStore, activeBranchKeyRecord)
      ).to.be.rejectedWith(
        'KMS ARN from DDB response item MUST be compatible with the configured KMS Key in the AWS KMS Configuration for this keystore'
      ))

      void (await expect(
        decryptBranchKey(branchKeyStore, ENCRYPTED_VERSION_BRANCH_KEY)
      ).to.be.rejectedWith(
        'KMS ARN from DDB response item MUST be compatible with the configured KMS Key in the AWS KMS Configuration for this keystore'
      ))
    })

    it('Active & versioned DDB records have custom EC', async () => {
      const configArn =
        'arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'
      const branchKeyId = '5ad89fbc-8011-4e18-95d5-31b165d8a10e'
      const branchKeyStore = new BranchKeyStoreNode({
        storage: { ddbTableName: DDB_TABLE_NAME },
        logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
        kmsConfiguration: { identifier: configArn },
      })

      const activeBranchKeyRecord =
        await branchKeyStore.storage.getEncryptedActiveBranchKey(branchKeyId)

      const activeBranchKey = await decryptBranchKey(
        branchKeyStore,
        activeBranchKeyRecord
      )

      const version = '8b867b79-3890-4f9b-9068-161fbc81ab3d'
      const versionedBranchKeyRecord =
        await branchKeyStore.storage.getEncryptedBranchKeyVersion(
          branchKeyId,
          version
        )
      const versionedBranchKey = await decryptBranchKey(
        branchKeyStore,
        versionedBranchKeyRecord
      )

      const kmsClient = new KMSClient({
        region: getRegionFromIdentifier(configArn),
      })
      let response = await kmsClient.send(
        new DecryptCommand({
          KeyId: configArn,
          CiphertextBlob: activeBranchKeyRecord.ciphertextBlob,
          EncryptionContext: activeBranchKeyRecord.encryptionContext,
        })
      )
      const expectedActiveBranchKey = Buffer.from(
        response.Plaintext as Uint8Array
      )

      response = await kmsClient.send(
        new DecryptCommand({
          KeyId: configArn,
          CiphertextBlob: versionedBranchKeyRecord.ciphertextBlob,
          EncryptionContext: versionedBranchKeyRecord.encryptionContext,
        })
      )
      const expectedVersionedBranchKey = Buffer.from(
        response.Plaintext as Uint8Array
      )

      expect(activeBranchKey).deep.equals(expectedActiveBranchKey)
      expect(versionedBranchKey).deep.equals(expectedVersionedBranchKey)
    })
  })
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=test
  //# - [Branch Key](./structures.md#branch-key) MUST be the [decrypted branch key material](#aws-kms-branch-key-decryption)

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=test
  //# - [Branch Key Id](./structures.md#branch-key-id) MUST be the `branch-key-id`

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=test
  //# - [Branch Key Version](./structures.md#branch-key-version)
  //# The version string MUST start with `branch:version:`.
  //# The remaining string encoded as UTF8 bytes MUST be the Branch Key version.

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
  //= type=test
  //# - [Encryption Context](./structures.md#encryption-context-3) MUST be constructed by
  //# [Custom Encryption Context From Authenticated Encryption Context](#custom-encryption-context-from-authenticated-encryption-context)
  describe('Test constructBranchKeyMaterials', () => {
    const branchKey = Buffer.alloc(32)

    it('Given active & versioned branch authenticated ECs with no custom EC', () => {
      const activeAuthEc = ENCRYPTED_ACTIVE_BRANCH_KEY.encryptionContext
      const activeBranchKeyMaterials = constructBranchKeyMaterials(
        branchKey,
        ENCRYPTED_ACTIVE_BRANCH_KEY
      )
      const versionedAuthEc = ENCRYPTED_VERSION_BRANCH_KEY.encryptionContext
      const versionedBranchKeyMaterials = constructBranchKeyMaterials(
        branchKey,
        ENCRYPTED_VERSION_BRANCH_KEY
      )

      expect(activeBranchKeyMaterials.branchKey()).deep.equals(branchKey)
      expect(versionedBranchKeyMaterials.branchKey()).deep.equals(branchKey)

      expect(activeBranchKeyMaterials.branchKeyIdentifier).equals(BRANCH_KEY_ID)
      expect(versionedBranchKeyMaterials.branchKeyIdentifier).equals(
        BRANCH_KEY_ID
      )

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
      //= type=test
      //# If the `type` attribute is equal to `"branch:ACTIVE"`
      //# then the authenticated encryption context MUST have a `version` attribute
      //# and the version string is this value.
      expect(activeBranchKeyMaterials.branchKeyVersion).deep.equals(
        Buffer.from(
          activeAuthEc[BRANCH_KEY_ACTIVE_VERSION_FIELD].substring(
            BRANCH_KEY_TYPE_PREFIX.length
          ),
          'utf-8'
        )
      )
      expect(versionedBranchKeyMaterials.branchKeyVersion).deep.equals(
        Buffer.from(
          versionedAuthEc[TYPE_FIELD].substring(BRANCH_KEY_TYPE_PREFIX.length),
          'utf-8'
        )
      )

      expect(activeBranchKeyMaterials.encryptionContext).deep.equals({})
      expect(versionedBranchKeyMaterials.encryptionContext).deep.equals({})
    })

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#custom-encryption-context-from-authenticated-encryption-context
    //= type=test
    //# For every key in the [encryption context](./structures.md#encryption-context-3)
    //# the string `aws-crypto-ec:` + the UTF8 decode of this key
    //# MUST exist as a key in the authenticated encryption context.
    //# Also, the value in the [encryption context](./structures.md#encryption-context-3) for this key
    //# MUST equal the value in the authenticated encryption context
    //# for the constructed key.
    it('Given active & versioned branch authenticated ECs with a custom EC', () => {
      const activeBranchKeyMaterials = constructBranchKeyMaterials(
        branchKey,
        new EncryptedHierarchicalKey(
          {
            ...ENCRYPTED_ACTIVE_BRANCH_KEY.encryptionContext,
            ...VALID_CUSTOM_ENCRYPTION_CONTEXT,
          },
          ENCRYPTED_ACTIVE_BRANCH_KEY.ciphertextBlob
        )
      )
      expect(activeBranchKeyMaterials.branchKey()).deep.equals(branchKey)
      expect(activeBranchKeyMaterials.branchKeyIdentifier).equals(BRANCH_KEY_ID)
      expect(activeBranchKeyMaterials.branchKeyVersion).deep.equals(
        Buffer.from(ENCRYPTED_ACTIVE_BRANCH_KEY.type.version, 'utf-8')
      )
      expect(activeBranchKeyMaterials.encryptionContext).deep.equals(
        VALID_CUSTOM_ENCRYPTION_CONTEXT
      )

      const versionedBranchKeyMaterials = constructBranchKeyMaterials(
        branchKey,
        new EncryptedHierarchicalKey(
          {
            ...ENCRYPTED_VERSION_BRANCH_KEY.encryptionContext,
            ...VALID_CUSTOM_ENCRYPTION_CONTEXT,
          },
          ENCRYPTED_VERSION_BRANCH_KEY.ciphertextBlob
        )
      )
      expect(versionedBranchKeyMaterials.branchKey()).deep.equals(branchKey)
      expect(versionedBranchKeyMaterials.branchKeyIdentifier).equals(
        BRANCH_KEY_ID
      )
      expect(versionedBranchKeyMaterials.branchKeyVersion).deep.equals(
        Buffer.from(ENCRYPTED_VERSION_BRANCH_KEY.type.version, 'utf-8')
      )
      expect(versionedBranchKeyMaterials.encryptionContext).deep.equals(
        VALID_CUSTOM_ENCRYPTION_CONTEXT
      )
    })
  })
})
