// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBClient } from '@aws-sdk/client-dynamodb'
import { KMSClient } from '@aws-sdk/client-kms'
import {
  needs,
  immutableClass,
  readOnlyProperty,
} from '@aws-crypto/material-management'
import {
  BRANCH_KEY_TYPE_PREFIX,
  BRANCH_KEY_IDENTIFIER_FIELD,
  TABLE_FIELD,
  TYPE_FIELD,
  KEY_CREATE_TIME_FIELD,
  HIERARCHY_VERSION_FIELD,
  KMS_FIELD,
  BRANCH_KEY_ACTIVE_VERSION_FIELD,
  BRANCH_KEY_ACTIVE_TYPE,
} from './constants'
import { KmsConfig } from './kms_config'

export type BranchKeyVersionType = `${typeof BRANCH_KEY_TYPE_PREFIX}${string}`
export type ActiveKeyEncryptionContext = {
  [BRANCH_KEY_IDENTIFIER_FIELD]: string
  [TABLE_FIELD]: string
  [TYPE_FIELD]: typeof BRANCH_KEY_ACTIVE_TYPE
  [KEY_CREATE_TIME_FIELD]: string
  [HIERARCHY_VERSION_FIELD]: string
  [KMS_FIELD]: string
  [BRANCH_KEY_ACTIVE_VERSION_FIELD]: BranchKeyVersionType
  [index: string]: string
}
export type VersionKeyEncryptionContext = {
  [BRANCH_KEY_IDENTIFIER_FIELD]: string
  [TABLE_FIELD]: string
  [TYPE_FIELD]: BranchKeyVersionType
  [KEY_CREATE_TIME_FIELD]: string
  [HIERARCHY_VERSION_FIELD]: string
  [KMS_FIELD]: string
  [index: string]: string
}
export type BranchKeyEncryptionContext =
  | ActiveKeyEncryptionContext
  | VersionKeyEncryptionContext

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#activehierarchicalsymmetric
//= type=implication
//# A structure that MUST have one member,
//# the UTF8 Encoded value of the version of the branch key.
export class ActiveHierarchicalSymmetricVersion {
  public declare readonly version: string

  constructor(activeVersion: BranchKeyVersionType) {
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
    //# If the `type` attribute is equal to `"branch:ACTIVE"`
    //# then the authenticated encryption context MUST have a `version` attribute
    //# and the version string is this value.
    needs(
      activeVersion.startsWith(BRANCH_KEY_TYPE_PREFIX),
      'Unexpected branch key type.'
    )
    readOnlyProperty(
      this,
      'version',
      activeVersion.substring(BRANCH_KEY_TYPE_PREFIX.length)
    )

    Object.freeze(this)
  }
}
immutableClass(ActiveHierarchicalSymmetricVersion)

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#hierarchicalsymmetric
//= type=implication
//# A structure that MUST have one member,
//# the UTF8 Encoded value of the version of the branch key.
export class HierarchicalSymmetricVersion {
  public declare readonly version: string

  constructor(type_field: BranchKeyVersionType) {
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
    //# If the `type` attribute start with `"branch:version:"` then the version string MUST be equal to this value.
    needs(
      type_field.startsWith(BRANCH_KEY_TYPE_PREFIX),
      'Type does not start with `branch:version:`'
    )
    readOnlyProperty(
      this,
      'version',
      type_field.substring(BRANCH_KEY_TYPE_PREFIX.length)
    )
    Object.freeze(this)
  }
}
immutableClass(HierarchicalSymmetricVersion)

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#type
//= type=implication
//# A union that MUST hold the following three options
//# - ActiveHierarchicalSymmetricVersion [ActiveHierarchicalSymmetric](#activehierarchicalsymmetric)
//# - HierarchicalSymmetricVersion [HierarchicalSymmetric](#hierarchicalsymmetric)
//# - ActiveHierarchicalSymmetricBeacon

export type Type =
  | ActiveHierarchicalSymmetricVersion
  | HierarchicalSymmetricVersion

export class EncryptedHierarchicalKey {
  //= aws-encryption-sdk-specification/framework/key-store/key-storage.md#encryptedhierarchicalkey
  //= type=implication
  //# This structure MUST include all of the following fields:
  //# - [BranchKeyId](./structures.md#branch-key-id)
  //# - [Type](#type)
  //# - CreateTime: Timestamp in ISO 8601 format in UTC, to microsecond precision.
  //# - KmsArn: The AWS KMS Key ARN used to protect the CiphertextBlob value.
  //# - [EncryptionContext](./structures.md#encryption-context-3)
  //# - CiphertextBlob: The encrypted binary for the hierarchical key.
  public declare readonly branchKeyId: string
  public declare readonly type: Type
  public declare readonly createTime: string
  public declare readonly kmsArn: string
  public declare readonly encryptionContext:
    | ActiveKeyEncryptionContext
    | VersionKeyEncryptionContext
  public declare readonly ciphertextBlob: Uint8Array

  constructor(
    encryptionContext: ActiveKeyEncryptionContext | VersionKeyEncryptionContext,
    ciphertextBlob: Uint8Array
  ) {
    readOnlyProperty(
      this,
      'branchKeyId',
      encryptionContext[BRANCH_KEY_IDENTIFIER_FIELD]
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context
    //# The `type` attribute MUST either be equal to `"branch:ACTIVE"` or start with `"branch:version:"`.
    needs(
      encryptionContext[TYPE_FIELD] == BRANCH_KEY_ACTIVE_TYPE ||
        encryptionContext[TYPE_FIELD].startsWith(BRANCH_KEY_TYPE_PREFIX),
      'Unexpected branch key type.'
    )

    readOnlyProperty(
      this,
      'type',
      encryptionContext[TYPE_FIELD] == BRANCH_KEY_ACTIVE_TYPE
        ? new ActiveHierarchicalSymmetricVersion(
            encryptionContext[BRANCH_KEY_ACTIVE_VERSION_FIELD]
          )
        : new HierarchicalSymmetricVersion(encryptionContext[TYPE_FIELD])
    )
    readOnlyProperty(
      this,
      'createTime',
      encryptionContext[KEY_CREATE_TIME_FIELD]
    )
    readOnlyProperty(this, 'kmsArn', encryptionContext[KMS_FIELD])
    readOnlyProperty(
      this,
      'encryptionContext',
      Object.freeze({ ...encryptionContext })
    )
    readOnlyProperty(this, 'ciphertextBlob', ciphertextBlob)

    Object.freeze(this)
  }
}
immutableClass(EncryptedHierarchicalKey)

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#interface
//= type=implication
//# The KeyStorageInterface MUST support the following operations:
export interface IBranchKeyStorage {
  //= aws-encryption-sdk-specification/framework/key-store/key-storage.md#interface
  //= type=implication
  //# - [GetEncryptedActiveBranchKey](#getencryptedactivebranchkey)
  //# - [GetEncryptedBranchKeyVersion](#getencryptedbranchkeyversion)

  //= aws-encryption-sdk-specification/framework/key-store/key-storage.md#getencryptedactivebranchkey
  //= type=implication
  //# The GetEncryptedActiveBranchKey caller MUST provide the same inputs as the [GetActiveBranchKey](../branch-key-store.md#getactivebranchkey) operation.

  //= aws-encryption-sdk-specification/framework/key-store/key-storage.md#getencryptedactivebranchkey
  //= type=implication
  //# It MUST return an [EncryptedHierarchicalKey](#encryptedhierarchicalkey).
  getEncryptedActiveBranchKey(
    branchKeyId: string
  ): Promise<EncryptedHierarchicalKey>

  //= aws-encryption-sdk-specification/framework/key-store/key-storage.md#getencryptedbranchkeyversion
  //= type=implication
  //# The GetEncryptedBranchKeyVersion caller MUST provide the same inputs as the [GetBranchKeyVersion](../branch-key-store.md#getbranchkeyversion) operation.

  //= aws-encryption-sdk-specification/framework/key-store/key-storage.md#getencryptedbranchkeyversion
  //= type=implication
  //# It MUST return an [EncryptedHierarchicalKey](#encryptedhierarchicalkey).
  getEncryptedBranchKeyVersion(
    branchKeyId: string,
    branchKeyVersion: string
  ): Promise<EncryptedHierarchicalKey>

  //= aws-encryption-sdk-specification/framework/key-store/key-storage.md#interface
  //= type=implication
  //# - [GetKeyStorageInfo](#getkeystorageinfo)

  //= aws-encryption-sdk-specification/framework/key-store/key-storage.md#getkeystorageinfo
  //= type=implication
  //# It MUST return the physical table name.
  getKeyStorageInfo(): { name: string; logicalName: string }
}

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#type
//= type=exception
//# - ActiveHierarchicalSymmetricBeacon

export interface DynamoDBTable {
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#dynamodbtable
  //= type=implication
  //# A DynamoDBTable configuration MUST take the DynamoDB table name.
  ddbTableName: string
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#dynamodbtable
  //= type=implication
  //# A DynamoDBTable configuration MAY take [DynamoDb Client](#dynamodb-client).
  ddbClient?: DynamoDBClient
}

//= aws-encryption-sdk-specification/framework/branch-key-store.md#storage
//# This configures how the Keystore will get encrypted data.
//# There are two valid storage options:
//#
//# - DynamoDBTable
//# - KeyStorage
export type Storage = DynamoDBTable | IBranchKeyStorage

export interface AwsKms {
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#awskms
  //= type=implication
  //# An AwsKms configuration MAY take a list of AWS KMS [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
  grantTokens?: string[]
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#awskms
  //= type=implication
  //# An AwsKms configuration MAY take an [AWS KMS SDK client](#awskms).
  kmsClient?: KMSClient
}

export type KeyManagement = AwsKms

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//# The following inputs MAY be specified to create a KeyStore:
//# - [ID](#keystore-id)

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//# - [Storage](#storage)

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//# - [KeyManagement](#keymanagement)

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//# The following inputs MUST be specified to create a KeyStore:
//# - [AWS KMS Configuration](#aws-kms-configuration)
//# - [Logical KeyStore Name](#logical-keystore-name)
export interface BranchKeyStoreNodeInput {
  logicalKeyStoreName: string
  storage: Storage
  keyManagement?: KeyManagement
  kmsConfiguration: KmsConfig
  keyStoreId?: string
}

// This is a limited release for JS only.
// The full Key Store operations are available
// in the AWS Cryptographic Material Providers library
// in various languages (Java, .Net, Python, Rust...)

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#interface
//= type=exception
//# - [WriteNewEncryptedBranchKey](#writenewencryptedbranchkey)
//# - [WriteNewEncryptedBranchKeyVersion](#writenewencryptedbranchkeyversion)

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#interface
//= type=exception
//# - [GetEncryptedBeaconKey](#getencryptedbeaconkey)

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#writenewencryptedbranchkey
//= type=exception
//# The WriteNewEncryptedBranchKey caller MUST provide:

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#writenewencryptedbranchkeyversion
//= type=exception
//# The WriteNewEncryptedBranchKeyVersion caller MUST provide:

//= aws-encryption-sdk-specification/framework/key-store/key-storage.md#getencryptedbeaconkey
//= type=exception
//# The GetEncryptedBeaconKey caller MUST provide the same inputs as the [GetBeaconKey](../branch-key-store.md#getbeaconkey) operation.
//# It MUST return an [EncryptedHierarchicalKey](#encryptedhierarchicalkey).
