// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  IBranchKeyStorage,
  EncryptedHierarchicalKey,
  ActiveHierarchicalSymmetricVersion,
  HierarchicalSymmetricVersion,
} from './types'
import { DynamoDBClient } from '@aws-sdk/client-dynamodb'
import {
  getBranchKeyItem,
  validateBranchKeyRecord,
  constructAuthenticatedEncryptionContext,
} from './branch_keystore_helpers'

import {
  BRANCH_KEY_ACTIVE_TYPE,
  BRANCH_KEY_TYPE_PREFIX,
  BRANCH_KEY_FIELD,
} from './constants'
import {
  immutableClass,
  needs,
  readOnlyProperty,
} from '@aws-crypto/material-management'

//= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#initialization
//= type=implication
//# The following inputs MUST be specified to create a Dynamodb Key Storage Interface:
//# - [DynamoDb Client](#dynamodb-client)
//# - [Table Name](#table-name)
//# - [Logical KeyStore Name](#logical-keystore-name)
export interface DynamoDBKeyStorageInput {
  ddbTableName: string
  logicalKeyStoreName: string
  ddbClient: DynamoDBClient
}

//= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#operations
//= type=implication
//# The Dynamodb Key Storage Interface MUST implement the [key storage interface](./key-storage.md#interface).
export class DynamoDBKeyStorage implements IBranchKeyStorage {
  public declare readonly ddbTableName: string
  public declare readonly logicalKeyStoreName: string
  public declare readonly ddbClient: DynamoDBClient

  constructor({
    ddbTableName,
    logicalKeyStoreName,
    ddbClient,
  }: DynamoDBKeyStorageInput) {
    /* Precondition: DDB table name must be a string */
    needs(typeof ddbTableName === 'string', 'DDB table name must be a string')
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#table-name
    //# The table name of the DynamoDb table that backs this Keystore.
    needs(ddbTableName, 'DynamoDb table name required')

    needs(
      typeof logicalKeyStoreName === 'string',
      'DDB table name must be a string'
    )

    /* Precondition: DDB client must be a DynamoDBClient */
    needs(
      ddbClient instanceof DynamoDBClient,
      'DDB client must be a DynamoDBClient'
    )

    readOnlyProperty(this, 'ddbTableName', ddbTableName)
    readOnlyProperty(this, 'ddbClient', ddbClient)
    readOnlyProperty(this, 'logicalKeyStoreName', logicalKeyStoreName)

    // make this instance immutable
    Object.freeze(this)
  }

  public async getEncryptedActiveBranchKey(
    branchKeyId: string
  ): Promise<EncryptedHierarchicalKey> {
    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedactivebranchkey
    //# To get the active version for the branch key id from the keystore
    //# this operation MUST call AWS DDB `GetItem`
    //# using the `branch-key-id` as the Partition Key and `"branch:ACTIVE"` value as the Sort Key.

    // get the ddb response item using the partition & sort keys
    const ddbBranchKeyItem = await getBranchKeyItem(
      this,
      branchKeyId,
      BRANCH_KEY_ACTIVE_TYPE
    )
    // validate and form the branch key record

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedactivebranchkey
    //# If the record does not contain the defined fields, this operation MUST fail.

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedactivebranchkey
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).
    const ddbBranchKeyRecord = validateBranchKeyRecord(ddbBranchKeyItem)
    // construct an encryption context from the record
    const authenticatedEncryptionContext =
      constructAuthenticatedEncryptionContext(this, ddbBranchKeyRecord)

    const encrypted = new EncryptedHierarchicalKey(
      authenticatedEncryptionContext,
      ddbBranchKeyRecord[BRANCH_KEY_FIELD]
    )

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedactivebranchkey
    //# The returned EncryptedHierarchicalKey MUST have the same identifier as the input.
    needs(encrypted.branchKeyId == branchKeyId, 'Unexpected branch key id.')

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedactivebranchkey
    //# The returned EncryptedHierarchicalKey MUST have a type of ActiveHierarchicalSymmetricVersion.
    needs(
      encrypted.type instanceof ActiveHierarchicalSymmetricVersion,
      'Unexpected type. Not an active record.'
    )

    return encrypted
  }

  public async getEncryptedBranchKeyVersion(
    branchKeyId: string,
    branchKeyVersion: string
  ): Promise<EncryptedHierarchicalKey> {
    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedbranchkeyversion
    //# To get a branch key from the keystore this operation MUST call AWS DDB `GetItem`
    //# using the `branch-key-id` as the Partition Key and "branch:version:" + `branchKeyVersion` value as the Sort Key.

    // get the ddb response item using the partition & sort keys
    const ddbBranchKeyItem = await getBranchKeyItem(
      this,
      branchKeyId,
      BRANCH_KEY_TYPE_PREFIX + branchKeyVersion
    )

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedbranchkeyversion
    //# If the record does not contain the defined fields, this operation MUST fail.

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedbranchkeyversion
    //# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).

    // validate and form the branch key record
    const ddbBranchKeyRecord = validateBranchKeyRecord(ddbBranchKeyItem)
    // construct an encryption context from the record
    const authenticatedEncryptionContext =
      constructAuthenticatedEncryptionContext(this, ddbBranchKeyRecord)

    const encrypted = new EncryptedHierarchicalKey(
      authenticatedEncryptionContext,
      ddbBranchKeyRecord[BRANCH_KEY_FIELD]
    )

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedbranchkeyversion
    //# The returned EncryptedHierarchicalKey MUST have the same identifier as the input.
    needs(encrypted.branchKeyId == branchKeyId, 'Unexpected branch key id.')

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedbranchkeyversion
    //# The returned EncryptedHierarchicalKey MUST have the same version as the input.
    needs(
      encrypted.type.version == branchKeyVersion,
      'Unexpected branch key version.'
    )

    //= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedbranchkeyversion
    //# The returned EncryptedHierarchicalKey MUST have a type of HierarchicalSymmetricVersion.
    needs(
      encrypted.type instanceof HierarchicalSymmetricVersion,
      'Unexpected type. Not an version record.'
    )

    return encrypted
  }

  getKeyStorageInfo() {
    return {
      name: this.ddbTableName,
      logicalName: this.logicalKeyStoreName,
    }
  }
}

immutableClass(DynamoDBKeyStorage)

// This is a limited release for JS only.
// The full Key Store operations are available
// in the AWS Cryptographic Material Providers library
// in various languages (Java, .Net, Python, Rust...)

//= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#writenewencryptedbranchkey
//= type=exception
//# To add the branch keys and a beacon key to the keystore the
//# operation MUST call [Amazon DynamoDB API TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).
//# The call to Amazon DynamoDB TransactWriteItems MUST use the configured Amazon DynamoDB Client to make the call.
//# The operation MUST call Amazon DynamoDB TransactWriteItems with a request constructed as follows:

//= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#writenewencryptedbranchkey
//= type=exception
//# If DDB TransactWriteItems is successful, this operation MUST return a successful response containing no additional data.
//# Otherwise, this operation MUST yield an error.

//= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#writenewencryptedbranchkeyversion
//= type=exception
//# To add the new branch key to the keystore,
//# the operation MUST call [Amazon DynamoDB API TransactWriteItems](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).
//# The call to Amazon DynamoDB TransactWriteItems MUST use the configured Amazon DynamoDB Client to make the call.
//# The operation MUST call Amazon DynamoDB TransactWriteItems with a request constructed as follows:

//= aws-encryption-sdk-specification/framework/key-store/dynamodb-key-storage.md#getencryptedbeaconkey
//= type=exception
//# To get a branch key from the keystore this operation MUST call AWS DDB `GetItem`
//# using the `branch-key-id` as the Partition Key and "beacon:ACTIVE" value as the Sort Key.
//# The AWS DDB response MUST contain the fields defined in the [branch keystore record format](#record-format).
//# The returned EncryptedHierarchicalKey MUST have the same identifier as the input.
//# The returned EncryptedHierarchicalKey MUST have a type of ActiveHierarchicalSymmetricBeacon.
//# If the record does not contain the defined fields, this operation MUST fail.
