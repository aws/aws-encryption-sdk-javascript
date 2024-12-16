// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetItemCommand, DynamoDBClient } from '@aws-sdk/client-dynamodb'
import { KMSClient } from '@aws-sdk/client-kms'
import {
  needs,
  NodeBranchKeyMaterial,
  EncryptionContext,
} from '@aws-crypto/material-management'
import { unmarshall } from '@aws-sdk/util-dynamodb'
import { BranchKeyItem, BranchKeyRecord } from './branch_keystore_structures'
import { EncryptedHierarchicalKey, BranchKeyEncryptionContext } from './types'
// import { IBranchKeyStoreNode } from './branch_keystore'
import { DecryptCommand } from '@aws-sdk/client-kms'
import { KmsKeyConfig } from './kms_config'
import {
  PARTITION_KEY,
  SORT_KEY,
  TABLE_FIELD,
  CUSTOM_ENCRYPTION_CONTEXT_FIELD_PREFIX,
  BRANCH_KEY_IDENTIFIER_FIELD,
  TYPE_FIELD,
  KEY_CREATE_TIME_FIELD,
  HIERARCHY_VERSION_FIELD,
  KMS_FIELD,
  BRANCH_KEY_FIELD,
  BRANCH_KEY_ACTIVE_VERSION_FIELD,
  BRANCH_KEY_TYPE_PREFIX,
  BRANCH_KEY_ACTIVE_TYPE,
  BEACON_KEY_TYPE_VALUE,
  POTENTIAL_BRANCH_KEY_RECORD_FIELDS,
} from './constants'

/**
 * This utility function uses a partition and sort key to query for a single branch
 * keystore record
 * @param ddbClient
 * @param ddbTableName
 * @param partitionValue
 * @param sortValue
 * @returns A DDB response item representing the branch keystore record
 * @throws 'Record not found in DynamoDB' if the query yields no hits for a
 * branch key record
 */
export async function getBranchKeyItem(
  {
    ddbClient,
    ddbTableName,
  }: {
    ddbClient: DynamoDBClient
    ddbTableName: string
  },
  partitionValue: string,
  sortValue: string
): Promise<BranchKeyItem> {
  // create a getItem command with the querying partition and sort keys
  // send the query for DDB to run
  // get the response
  const response = await ddbClient.send(
    new GetItemCommand({
      TableName: ddbTableName,
      Key: {
        [PARTITION_KEY]: { S: partitionValue },
        [SORT_KEY]: { S: sortValue },
      },
    })
  )
  // the response has an Item field if the branch keystore record was found
  const responseItem = response.Item
  // error out if there is not Item field (record not found)
  needs(
    responseItem,
    `A branch key record with ${PARTITION_KEY}=${partitionValue} and ${SORT_KEY}=${sortValue} was not found in DynamoDB`
  )
  // at this point, we got back a record so convert the DDB response item into
  // a more JS-friendly object
  return unmarshall(responseItem)
}

/**
 * This utility function validates the DDB response item against the required
 * record fromat and transforms the item into a branch key record
 * @param item is the DDB response item representing a branch keystore record
 * @returns a validated branch key record abiding by the proper record format
 * @throws `Branch keystore record does not contain a ${BRANCH_KEY_IDENTIFIER_FIELD} field of type string`
 * @throws `Branch keystore record does not contain a valid ${TYPE_FIELD} field of type string`
 * @throws `Branch keystore record does not contain a ${BRANCH_KEY_ACTIVE_VERSION_FIELD} field of type string`
 * if the type field is "branch:ACTIVE" but there is no version field in the DDB
 * response item
 * @throws `Branch keystore record does not contain ${BRANCH_KEY_FIELD} field of type Uint8Array`
 * @throws `Branch keystore record does not contain ${KMS_FIELD} field of type string`
 * @throws `Branch keystore record does not contain ${KEY_CREATE_TIME_FIELD} field of type string`
 * @throws `Branch keystore record does not contain ${HIERARCHY_VERSION_FIELD} field of type number`
 * @throws `Custom encryption context key ${field} should be prefixed with ${CUSTOM_ENCRYPTION_CONTEXT_FIELD_PREFIX}`
 * if there are additional fields within the response item that
 * don't follow the proper custom encryption context key naming convention
 */
//= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
//# A branch key record MUST include the following key-value pairs:
export function validateBranchKeyRecord(item: BranchKeyItem): BranchKeyRecord {
  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
  //# 1. `branch-key-id` : Unique identifier for a branch key; represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
  needs(
    BRANCH_KEY_IDENTIFIER_FIELD in item &&
      typeof item[BRANCH_KEY_IDENTIFIER_FIELD] === 'string',
    `Branch keystore record does not contain a ${BRANCH_KEY_IDENTIFIER_FIELD} field of type string`
  )

  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
  //# 1. `type` : One of the following; represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
  //#    - The string literal `"beacon:ACTIVE"`. Then `enc` is the wrapped beacon key.
  //#    - The string `"branch:version:"` + `version`, where `version` is the Branch Key Version. Then `enc` is the wrapped branch key.
  //#    - The string literal `"branch:ACTIVE"`. Then `enc` is the wrapped beacon key of the active version. Then
  needs(
    TYPE_FIELD in item &&
      typeof item[TYPE_FIELD] === 'string' &&
      (item[TYPE_FIELD] === BRANCH_KEY_ACTIVE_TYPE ||
        item[TYPE_FIELD].startsWith(BRANCH_KEY_TYPE_PREFIX) ||
        item[TYPE_FIELD] === BEACON_KEY_TYPE_VALUE),
    `Branch keystore record does not contain a valid ${TYPE_FIELD} field of type string`
  )

  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
  //# 1. `version` : Only exists if `type` is the string literal `"branch:ACTIVE"`.
  //#   Then it is the Branch Key Version. represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
  if (item[TYPE_FIELD] === BRANCH_KEY_ACTIVE_TYPE) {
    needs(
      BRANCH_KEY_ACTIVE_VERSION_FIELD in item &&
        typeof item[BRANCH_KEY_ACTIVE_VERSION_FIELD] === 'string',
      `Branch keystore record does not contain a ${BRANCH_KEY_ACTIVE_VERSION_FIELD} field of type string`
    )
  }

  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
  //# 1. `enc` : Encrypted version of the key;
  //#   represented as [AWS DDB Binary](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
  needs(
    BRANCH_KEY_FIELD in item && item[BRANCH_KEY_FIELD] instanceof Uint8Array,
    `Branch keystore record does not contain ${BRANCH_KEY_FIELD} field of type Uint8Array`
  )

  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
  //# 1. `kms-arn`: The AWS KMS Key ARN used to generate the `enc` value.
  //#   represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
  needs(
    KMS_FIELD in item && typeof item[KMS_FIELD] === 'string',
    `Branch keystore record does not contain ${KMS_FIELD} field of type string`
  )

  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
  //# 1. `create-time`: Timestamp in ISO 8601 format in UTC, to microsecond precision.
  //#   Represented as [AWS DDB String](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
  needs(
    KEY_CREATE_TIME_FIELD in item &&
      typeof item[KEY_CREATE_TIME_FIELD] === 'string',
    `Branch keystore record does not contain ${KEY_CREATE_TIME_FIELD} field of type string`
  )

  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
  //# 1. `hierarchy-version`: Version of the hierarchical keyring;
  //#   represented as [AWS DDB Number](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html#HowItWorks.DataTypes)
  needs(
    HIERARCHY_VERSION_FIELD in item &&
      typeof item[HIERARCHY_VERSION_FIELD] === 'number',
    `Branch keystore record does not contain ${HIERARCHY_VERSION_FIELD} field of type number`
  )

  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#record-format
  //# A branch key record MAY include [custom encryption context](../branch-key-store.md#custom-encryption-context) key-value pairs.
  //# These attributes should be prefixed with `aws-crypto-ec:` the same way they are for [AWS KMS encryption context](../branch-key-store.md#encryption-context).
  for (const field in item) {
    if (!POTENTIAL_BRANCH_KEY_RECORD_FIELDS.includes(field)) {
      needs(
        field.startsWith(CUSTOM_ENCRYPTION_CONTEXT_FIELD_PREFIX),
        `Custom encryption context key ${field} should be prefixed with ${CUSTOM_ENCRYPTION_CONTEXT_FIELD_PREFIX}`
      )
    }
  }

  // serialize the DDB response item as a more well-defined and validated branch
  // key record object
  return Object.assign({}, item) as BranchKeyRecord
}

/**
 * This utility function builds an authenticated encryption context from the DDB
 * response item
 * @param logicalKeyStoreName
 * @param branchKeyRecord
 * @returns authenticated encryption context
 */
export function constructAuthenticatedEncryptionContext(
  //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#logical-keystore-name
  //# It is not stored on the items in the so it MUST be added
  //# to items retrieved from the table.
  { logicalKeyStoreName }: { logicalKeyStoreName: string },
  branchKeyRecord: BranchKeyRecord
): BranchKeyEncryptionContext {
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#encryption-context
  //# This section describes how the AWS KMS encryption context is built
  //# from an [encrypted hierarchical key](./key-store/key-storage.md#encryptedhierarchicalkey).
  //#
  //# The following encryption context keys are shared:
  //#
  //# - MUST have a `branch-key-id` attribute
  //# - The `branch-key-id` field MUST not be an empty string
  //# - MUST have a `type` attribute
  //# - The `type` field MUST not be an empty string
  //# - MUST have a `create-time` attribute
  //# - MUST have a `tablename` attribute to store the logicalKeyStoreName
  //# - MUST have a `kms-arn` attribute
  //# - MUST have a `hierarchy-version`
  //# - MUST NOT have a `enc` attribute
  //#
  //# Any additionally attributes in the EncryptionContext
  //# of the [encrypted hierarchical key](./key-store/key-storage.md#encryptedhierarchicalkey)
  //# MUST be added to the encryption context.
  //#

  // the encryption context is a string to string map, so serialize the branch
  // key record to this form
  // filter out the enc field
  // add in the tablename key-value pair
  const encryptionContext: BranchKeyEncryptionContext = {
    ...Object.fromEntries(
      Object.entries(branchKeyRecord)
        .map(([key, value]) => [key, value.toString()])
        .filter(([key]) => key !== BRANCH_KEY_FIELD)
    ),
    [TABLE_FIELD]: logicalKeyStoreName,
  }
  return encryptionContext
}

/**
 * This utility function decrypts a branch key via KMS
 * @param kmsConfiguration
 * @param grantTokens
 * @param kmsClient
 * @param branchKeyRecord
 * @param authenticatedEncryptionContext
 * @returns the unencrypted branch key
 * @throws 'KMS ARN from DDB response item MUST be compatible with the configured KMS Key in the AWS KMS Configuration for this keystore'
 * @throws 'KMS branch key decryption failed' if the KMS response does not
 * contain a plaintext field representing the plaintext branch data key
 */
export async function decryptBranchKey(
  {
    kmsConfiguration,
    grantTokens,
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //# The operation MUST use the configured `KMS SDK Client` to decrypt the value of the branch key field.
    kmsClient,
  }: {
    kmsClient: KMSClient
    kmsConfiguration: Readonly<KmsKeyConfig>
    grantTokens?: ReadonlyArray<string>
  },
  encryptedHierarchicalKey: EncryptedHierarchicalKey
): Promise<Buffer> {
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#discovery
  //# The Keystore MAY use the KMS Key ARNs already
  //# persisted to the backing DynamoDB table,
  //# provided they are in records created
  //# with an identical Logical Keystore Name.

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#mrdiscovery
  //# The Keystore MAY use the KMS Key ARNs already
  //# persisted to the backing DynamoDB table,
  //# provided they are in records created
  //# with an identical Logical Keystore Name.

  const KeyId = kmsConfiguration.getCompatibleArnArn(
    encryptedHierarchicalKey.kmsArn
  )

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
  //# When calling [AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html),
  //# the keystore operation MUST call with a request constructed as follows:
  const response = await kmsClient.send(
    new DecryptCommand({
      KeyId,
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //# - `CiphertextBlob` MUST be the `CiphertextBlob` attribute value on the provided EncryptedHierarchicalKey
      CiphertextBlob: encryptedHierarchicalKey.ciphertextBlob,
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //# - `EncryptionContext` MUST be the [encryption context](#encryption-context) of the provided EncryptedHierarchicalKey
      EncryptionContext: encryptedHierarchicalKey.encryptionContext,
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //# - `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
      GrantTokens: grantTokens ? grantTokens.slice() : grantTokens,
    })
  )

  // error out if for some reason the KMS response does not contain the
  // plaintext branch data key
  needs(response.Plaintext, 'KMS branch key decryption failed')
  // convert the unencrypted branch key into a Node Buffer
  return Buffer.from(response.Plaintext as Uint8Array)
}

/**
 * This utility function constructs branch key materials from the authenticated
 * encryption context
 * @param branchKey
 * @param branchKeyId
 * @param authenticatedEncryptionContext
 * @returns branch key materials
 * @throws 'Unable to get branch key version to construct branch key materials from authenticated encryption context'
 * if the type in the EC is invalid
 */
export function constructBranchKeyMaterials(
  branchKey: Buffer,
  encryptedHierarchicalKey: EncryptedHierarchicalKey
): NodeBranchKeyMaterial {
  return new NodeBranchKeyMaterial(
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
    //# - [Branch Key](./structures.md#branch-key) MUST be the [decrypted branch key material](#aws-kms-branch-key-decryption)
    branchKey,
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
    //# - [Branch Key Id](./structures.md#branch-key-id) MUST be the `branch-key-id`
    encryptedHierarchicalKey.branchKeyId,
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
    //# - [Branch Key Version](./structures.md#branch-key-version)
    //# The version string MUST start with `branch:version:`.
    //# The remaining string encoded as UTF8 bytes MUST be the Branch Key version.
    encryptedHierarchicalKey.type.version,
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
    //# - [Encryption Context](./structures.md#encryption-context-3) MUST be constructed by
    //# [Custom Encryption Context From Authenticated Encryption Context](#custom-encryption-context-from-authenticated-encryption-context)
    constructCustomEncryptionContext(encryptedHierarchicalKey.encryptionContext)
  )
}

/**
 * This is a utility function that constructs a custom encryption context from
 * an authenticated encryption context
 * @param authenticatedEncryptionContext
 * @returns custom encryption context
 */
function constructCustomEncryptionContext(
  authenticatedEncryptionContext: EncryptionContext
) {
  const customEncryptionContext: EncryptionContext = {}

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#custom-encryption-context-from-authenticated-encryption-context
  //# For every key in the [encryption context](./structures.md#encryption-context-3)
  //# the string `aws-crypto-ec:` + the UTF8 decode of this key
  //# MUST exist as a key in the authenticated encryption context.
  //# Also, the value in the [encryption context](./structures.md#encryption-context-3) for this key
  //# MUST equal the value in the authenticated encryption context
  //# for the constructed key.
  for (const [key, value] of Object.entries(authenticatedEncryptionContext)) {
    if (key.startsWith(CUSTOM_ENCRYPTION_CONTEXT_FIELD_PREFIX)) {
      customEncryptionContext[key] = value
    }
  }

  return customEncryptionContext
}
