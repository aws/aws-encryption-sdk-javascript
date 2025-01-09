// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { KmsConfig, KmsKeyConfig } from './kms_config'
import { KMSClient } from '@aws-sdk/client-kms'
import { DynamoDBClient } from '@aws-sdk/client-dynamodb'
import {
  NodeBranchKeyMaterial,
  immutableClass,
  needs,
  readOnlyProperty,
} from '@aws-crypto/material-management'
import { v4 } from 'uuid'
import {
  constructBranchKeyMaterials,
  decryptBranchKey,
} from './branch_keystore_helpers'
import { KMS_CLIENT_USER_AGENT, TABLE_FIELD } from './constants'

import {
  IBranchKeyStorage,
  BranchKeyStoreNodeInput,
  ActiveHierarchicalSymmetricVersion,
  HierarchicalSymmetricVersion,
} from './types'
import { DynamoDBKeyStorage } from './dynamodb_key_storage'

//= aws-encryption-sdk-specification/framework/branch-key-store.md#operations
//= type=implication
//# The Keystore MUST support the following operations:

interface IBranchKeyStoreNode {
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#operations
  //= type=implication
  //# - [GetActiveBranchKey](#getactivebranchkey)
  getActiveBranchKey(branchKeyId: string): Promise<NodeBranchKeyMaterial>
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#operations
  //= type=implication
  //# - [GetBranchKeyVersion](#getbranchkeyversion)
  getBranchKeyVersion(
    branchKeyId: string,
    branchKeyVersion: string
  ): Promise<NodeBranchKeyMaterial>
  //= aws-encryption-sdk-specification/framework/branch-key-store.md#operations
  //= type=implication
  //# - [GetKeyStoreInfo](#getkeystoreinfo)
  getKeyStoreInfo(): KeyStoreInfoOutput
}

//= aws-encryption-sdk-specification/framework/branch-key-store.md#getkeystoreinfo
//= type=implication
//# This MUST include:
//# - [keystore id](#keystore-id)
//# - [keystore name](#table-name)
//# - [logical Keystore name](#logical-keystore-name)
//# - [AWS KMS Grant Tokens](#aws-kms-grant-tokens)
//# - [AWS KMS Configuration](#aws-kms-configuration)

export interface KeyStoreInfoOutput {
  keystoreId: string
  keystoreTableName: string
  logicalKeyStoreName: string
  grantTokens: string[]
  kmsConfiguration: KmsConfig
}

export class BranchKeyStoreNode implements IBranchKeyStoreNode {
  public declare readonly logicalKeyStoreName: string
  public declare readonly kmsConfiguration: Readonly<KmsKeyConfig>
  public declare readonly kmsClient: KMSClient
  public declare readonly keyStoreId: string
  public declare readonly grantTokens?: ReadonlyArray<string>
  public declare readonly storage: IBranchKeyStorage

  constructor({
    logicalKeyStoreName,
    storage,
    keyManagement,
    kmsConfiguration,
    keyStoreId,
  }: BranchKeyStoreNodeInput) {
    /* Precondition: Logical keystore name must be a string */
    needs(
      typeof logicalKeyStoreName === 'string',
      'Logical keystore name must be a string'
    )

    /* Precondition: KMS Configuration must be provided. */
    readOnlyProperty(
      this,
      'kmsConfiguration',
      new KmsKeyConfig(kmsConfiguration)
    )

    /* Precondition: KMS client must be a KMSClient */
    if (keyManagement?.kmsClient) {
      needs(
        keyManagement.kmsClient instanceof KMSClient,
        'KMS client must be a KMSClient'
      )
    }

    if (
      'getEncryptedActiveBranchKey' in storage &&
      'getEncryptedBranchKeyVersion' in storage
    ) {
      // JS does structural typing.

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If [Storage](#storage) is configured with [KeyStorage](#keystorage)
      //# then this MUST be the configured [KeyStorage interface](./key-store/key-storage.md#interface).
      this.storage = storage
    } else {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If [Storage](#storage) is not configured with [KeyStorage](#keystorage)
      //# a [default key storage](./key-store/default-key-storage.md#initialization) MUST be created.

      needs(
        !storage.ddbClient ||
          (storage.ddbClient as any) instanceof DynamoDBClient,
        'DDB client must be a DynamoDBClient'
      )
      this.storage = new DynamoDBKeyStorage({
        //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
        //# This constructed [default key storage](./key-store/default-key-storage.md#initialization)
        //# MUST be configured with either the [Table Name](#table-name) or the [DynamoDBTable](#dynamodbtable) table name
        //# depending on which one is configured.
        ddbTableName: storage.ddbTableName,
        //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
        //# This constructed [default key storage](./key-store/default-key-storage.md#overview)
        //# MUST be configured with the provided [logical keystore name](#logical-keystore-name).
        logicalKeyStoreName,
        ddbClient:
          //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
          //# This constructed [default key storage](./key-store/default-key-storage.md#initialization)
          //# MUST be configured with either the [DynamoDb Client](#dynamodb-client), the DDB client in the [DynamoDBTable](#dynamodbtable)
          //# or a constructed DDB client depending on what is configured.
          storage.ddbClient instanceof DynamoDBClient
            ? storage.ddbClient
            : new DynamoDBClient({
                //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
                //# If a DDB client needs to be constructed and the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
                //# a new DynamoDb client MUST be created with the region of the supplied KMS ARN.
                //#
                //# If a DDB client needs to be constructed and the AWS KMS Configuration is Discovery,
                //# a new DynamoDb client MUST be created with the default configuration.
                //#
                //# If a DDB client needs to be constructed and the AWS KMS Configuration is MRDiscovery,
                //# a new DynamoDb client MUST be created with the region configured in the MRDiscovery.
                region: this.kmsConfiguration.getRegion(),
              }),
      })
    }
    readOnlyProperty(this, 'storage', this.storage)

    needs(
      logicalKeyStoreName == this.storage.getKeyStorageInfo().logicalName,
      'Configured logicalKeyStoreName does not match configured storage interface.'
    )

    /* Precondition: Keystore id must be a string */
    if (keyStoreId) {
      needs(typeof keyStoreId === 'string', 'Keystore id must be a string')
    } else {
      // ensure it's strictly undefined and not some other falsey value
      keyStoreId = undefined
    }

    /* Precondition: Grant tokens must be a string array */
    if (keyManagement?.grantTokens) {
      needs(
        Array.isArray(keyManagement.grantTokens) &&
          keyManagement.grantTokens.every(
            (grantToken) => typeof grantToken === 'string'
          ),
        'Grant tokens must be a string array'
      )
    }

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#keystore-id
    //# The Identifier for this KeyStore.
    //# If one is not supplied, then a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt) MUST be used.
    readOnlyProperty(this, 'keyStoreId', keyStoreId ? keyStoreId : v4())
    /* Postcondition: If unprovided, the keystore id is a generated valid uuidv4 */

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-grant-tokens
    //# A list of AWS KMS [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
    readOnlyProperty(
      this,
      'grantTokens',
      keyManagement?.grantTokens || undefined
    )
    /* Postcondition: If unprovided, the grant tokens are undefined */

    // TODO: when other KMS configuration types/classes are supported for the keystore,
    // verify the configuration object type to determine how we instantiate the
    // KMS client. This will ensure safe type casting.
    readOnlyProperty(
      this,
      'kmsClient',
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If no AWS KMS client is provided one MUST be constructed.
      keyManagement?.kmsClient ||
        new KMSClient({
          //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
          //# If AWS KMS client needs to be constructed and the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
          //# a new AWS KMS client MUST be created with the region of the supplied KMS ARN.
          //#
          //# If AWS KMS client needs to be constructed and the AWS KMS Configuration is Discovery,
          //# a new AWS KMS client MUST be created with the default configuration.
          //#
          //# If AWS KMS client needs to be constructed and the AWS KMS Configuration is MRDiscovery,
          //# a new AWS KMS client MUST be created with the region configured in the MRDiscovery.
          region: this.kmsConfiguration.getRegion(),
          //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
          //# On initialization the KeyStore SHOULD
          //# append a user agent string to the AWS KMS SDK Client with
          //# the value `aws-kms-hierarchy`.
          customUserAgent: KMS_CLIENT_USER_AGENT,
        })
    )
    /* Postcondition: If unprovided, the KMS client is configured */

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#logical-keystore-name
    //# This name is cryptographically bound to all data stored in this table,
    //# and logically separates data between different tables.
    //#
    //# The logical keystore name MUST be bound to every created key.
    //#
    //# There needs to be a one to one mapping between DynamoDB Table Names and the Logical KeyStore Name.
    //# This value can be set to the DynamoDB table name itself, but does not need to.
    //#
    //# Controlling this value independently enables restoring from DDB table backups
    //# even when the table name after restoration is not exactly the same.
    needs(logicalKeyStoreName, 'Logical Keystore name required')
    readOnlyProperty(this, 'logicalKeyStoreName', logicalKeyStoreName)

    // make this instance immutable
    Object.freeze(this)
  }

  async getActiveBranchKey(
    branchKeyId: string
  ): Promise<NodeBranchKeyMaterial> {
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# On invocation, the caller:
    //#
    //# - MUST supply a `branch-key-id`
    needs(
      branchKeyId && typeof branchKeyId === 'string',
      'MUST supply a string branch key id'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# GetActiveBranchKey MUST get the active version for the branch key id from the keystore
    //# by calling the configured [KeyStorage interface's](./key-store/key-storage.md#interface)
    //# [GetEncryptedActiveBranchKey](./key-store/key-storage.md#getencryptedactivebranchkey)
    //# using the supplied `branch-key-id`.
    const activeEncryptedBranchKey =
      await this.storage.getEncryptedActiveBranchKey(branchKeyId)

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# Because the storage interface can be a custom implementation the key store needs to verify correctness.

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# GetActiveBranchKey MUST verify that the returned EncryptedHierarchicalKey MUST have the requested `branch-key-id`.
    needs(
      activeEncryptedBranchKey.branchKeyId == branchKeyId,
      'Unexpected branch key id.'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# GetActiveBranchKey MUST verify that the returned EncryptedHierarchicalKey is an ActiveHierarchicalSymmetricVersion.
    needs(
      activeEncryptedBranchKey.type instanceof
        ActiveHierarchicalSymmetricVersion,
      'Unexpected type. Not an version record.'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# GetActiveBranchKey MUST verify that the returned EncryptedHierarchicalKey MUST have a logical table name equal to the configured logical table name.
    needs(
      activeEncryptedBranchKey.encryptionContext[TABLE_FIELD] ==
        this.logicalKeyStoreName,
      'Unexpected logical table name.'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# If the branch key fails to decrypt, GetActiveBranchKey MUST fail.

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# The operation MUST decrypt the EncryptedHierarchicalKey according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.
    const branchKey = await decryptBranchKey(this, activeEncryptedBranchKey)

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# This GetActiveBranchKey MUST construct [branch key materials](./structures.md#branch-key-materials)
    //# according to [Branch Key Materials From Authenticated Encryption Context](#branch-key-materials-from-authenticated-encryption-context).
    const branchKeyMaterials = constructBranchKeyMaterials(
      branchKey,
      activeEncryptedBranchKey
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getactivebranchkey
    //# This operation MUST return the constructed [branch key materials](./structures.md#branch-key-materials).
    return branchKeyMaterials
  }

  async getBranchKeyVersion(
    branchKeyId: string,
    branchKeyVersion: string
  ): Promise<NodeBranchKeyMaterial> {
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# On invocation, the caller:
    //#
    //# - MUST supply a `branch-key-id`
    //# - MUST supply a `branchKeyVersion`
    needs(
      branchKeyId && typeof branchKeyId === 'string',
      'MUST supply a string branch key id'
    )
    needs(
      branchKeyId && branchKeyVersion,
      'MUST supply a string branch key version'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //= type=implication
    //# GetBranchKeyVersion MUST get the requested version for the branch key id from the keystore
    //# by calling the configured [KeyStorage interface's](./key-store/key-storage.md#interface)
    //# [GetEncryptedActiveBranchKey](./key-store/key-storage.md#getencryptedbranchkeyversion)
    //# using the supplied `branch-key-id`.
    const encryptedBranchKey = await this.storage.getEncryptedBranchKeyVersion(
      branchKeyId,
      branchKeyVersion
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# GetBranchKeyVersion MUST verify that the returned EncryptedHierarchicalKey MUST have the requested `branch-key-id`.
    needs(
      encryptedBranchKey.branchKeyId == branchKeyId,
      'Unexpected branch key id.'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# GetBranchKeyVersion MUST verify that the returned EncryptedHierarchicalKey MUST have the requested `branchKeyVersion`.
    needs(
      encryptedBranchKey.type.version == branchKeyVersion,
      'Unexpected branch key id.'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# GetActiveBranchKey MUST verify that the returned EncryptedHierarchicalKey is an HierarchicalSymmetricVersion.
    needs(
      encryptedBranchKey.type instanceof HierarchicalSymmetricVersion,
      'Unexpected type. Not an version record.'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# GetBranchKeyVersion MUST verify that the returned EncryptedHierarchicalKey MUST have a logical table name equal to the configured logical table name.
    needs(
      encryptedBranchKey.encryptionContext[TABLE_FIELD] ==
        this.logicalKeyStoreName,
      'Unexpected logical table name.'
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# If the branch key fails to decrypt, this operation MUST fail.

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# The operation MUST decrypt the branch key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.
    const branchKey = await decryptBranchKey(this, encryptedBranchKey)

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# This GetBranchKeyVersion MUST construct [branch key materials](./structures.md#branch-key-materials)
    //# according to [Branch Key Materials From Authenticated Encryption Context](#branch-key-materials-from-authenticated-encryption-context).
    const branchKeyMaterials = constructBranchKeyMaterials(
      branchKey,
      encryptedBranchKey
    )

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#getbranchkeyversion
    //# This operation MUST return the constructed [branch key materials](./structures.md#branch-key-materials).
    return branchKeyMaterials
  }

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#getkeystoreinfo
  //= type=implication
  //# This operation MUST return the keystore information in this keystore configuration.
  getKeyStoreInfo(): KeyStoreInfoOutput {
    return {
      keystoreId: this.keyStoreId,
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#getkeystoreinfo
      //= type=implication
      //# The [keystore name](#table-name) MUST be obtained
      //# from the configured [KeyStorage](./key-store/key-storage.md#interface)
      //# by calling [GetKeyStorageInfo](./key-store/key-storage.md#getkeystorageinfo).
      keystoreTableName: this.storage.getKeyStorageInfo().name,
      logicalKeyStoreName: this.logicalKeyStoreName,
      grantTokens: this.grantTokens ? this.grantTokens.slice() : [],
      kmsConfiguration: this.kmsConfiguration._config,
    }
  }
}

immutableClass(BranchKeyStoreNode)

// type guard
export function isIBranchKeyStoreNode(
  keyStore: any
): keyStore is BranchKeyStoreNode {
  return keyStore instanceof BranchKeyStoreNode
}

// The JS implementation is not encumbered with the legacy construction
// by passing DDB clients et al.
// So it can be simplified.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//= type=exception
//# - [AWS KMS Grant Tokens](#aws-kms-grant-tokens)

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//= type=exception
//# - [DynamoDb Client](#dynamodb-client)

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//= type=exception
//# - [Table Name](#table-name)
//# - [KMS Client](#kms-client)

//= aws-encryption-sdk-specification/framework/branch-key-store.md#operations
//= type=exception
//# - [CreateKeyStore](#createkeystore)
//# - [CreateKey](#createkey)
//# - [VersionKey](#versionkey)

//= aws-encryption-sdk-specification/framework/branch-key-store.md#operations
//= type=exception
//# - [GetBeaconKey](#getbeaconkey)

// Only `Storage` is defined as as input
// because JS was only released with this option.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//= type=exception
//# If neither [Storage](#storage) nor [Table Name](#table-name) is configured initialization MUST fail.
//# If both [Storage](#storage) and [Table Name](#table-name) are configured initialization MUST fail.
//# If both [Storage](#storage) and [DynamoDb Client](#dynamodb-client) are configured initialization MUST fail.

// Only `KeyManagement` is defined as as input
// because JS was only released with this option.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
//= type=exception
//# If both [KeyManagement](#keymanagement) and [KMS Client](#kms-client) are configured initialization MUST fail.
//# If both [KeyManagement](#keymanagement) and [Grant Tokens](#aws-kms-grant-tokens) are configured initialization MUST fail.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#createkeystore
//= type=exception
//# If a [table Name](#table-name) was not configured then CreateKeyStore MUST fail.
//#
//# This operation MUST first calls the DDB::DescribeTable API with the configured `tableName`.
//#
//# If the response is successful, this operation validates that the table has the expected
//# [KeySchema](#keyschema) as defined below.
//# If the [KeySchema](#keyschema) does not match
//# this operation MUST yield an error.
//# The table MAY have additional information,
//# like GlobalSecondaryIndex defined.
//#
//# If the client responds with a `ResourceNotFoundException`,
//# then this operation MUST continue and
//# MUST call [AWS DDB CreateTable](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html)
//# with the following specifics:
//#
//# - TableName is the configured tableName.
//# - [KeySchema](#keyschema) as defined below.
//#
//# If the operation fails to create table, the operation MUST fail.
//#
//# If the operation successfully creates a table, the operation MUST return the AWS DDB Table Arn
//# back to the caller.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#createkey
//= type=exception
//# The CreateKey caller MUST provide:
//#
//# - An optional branch key id
//# - An optional encryption context
//#
//# If an optional branch key id is provided
//# and no encryption context is provided this operation MUST fail.
//#
//# If the Keystore's KMS Configuration is `Discovery` or `MRDiscovery`,
//# this operation MUST fail.
//#
//# If no branch key id is provided,
//# then this operation MUST create a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt)
//# to be used as the branch key id.
//#
//# This operation MUST create a [branch key](structures.md#branch-key) and a [beacon key](structures.md#beacon-key) according to
//# the [Branch Key and Beacon Key Creation](#branch-key-and-beacon-key-creation) section.
//#
//# If creation of the keys are successful,
//# then the key store MUST call the configured [KeyStorage interface's](./key-store/key-storage.md#interface)
//# [WriteNewEncryptedBranchKey](./key-store/key-storage.md#writenewencryptedbranchkey) with these 3 [EncryptedHierarchicalKeys](./key-store/key-storage.md#encryptedhierarchicalkey).
//#
//# If writing to the keystore succeeds,
//# the operation MUST return the branch-key-id that maps to both
//# the branch key and the beacon key.
//#
//# Otherwise, this operation MUST yield an error.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-and-beacon-key-creation
//= type=exception
//# To create a branch key, this operation MUST take the following:
//#
//# - `branchKeyId`: The identifier
//# - `encryptionContext`: Additional encryption context to bind to the created keys
//#
//# This operation needs to generate the following:
//#
//# - `version`: a new guid. This guid MUST be [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt)
//# - `timestamp`: a timestamp for the current time.
//#   This timestamp MUST be in ISO 8601 format in UTC, to microsecond precision (e.g. “YYYY-MM-DDTHH:mm:ss.ssssssZ“)
//#
//# The wrapped Branch Keys, DECRYPT_ONLY and ACTIVE, MUST be created according to [Wrapped Branch Key Creation](#wrapped-branch-key-creation).
//#
//# To create a beacon key, this operation will continue to use the `branchKeyId` and `timestamp` as the [Branch Key](structures.md#branch-key).
//#
//# The operation MUST call [AWS KMS API GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).
//# The call to AWS KMS GenerateDataKeyWithoutPlaintext MUST use the configured AWS KMS client to make the call.
//# The operation MUST call AWS KMS GenerateDataKeyWithoutPlaintext with a request constructed as follows:
//#
//# - `KeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
//# - `NumberOfBytes` MUST be 32.
//# - `EncryptionContext` MUST be the [encryption context for beacon keys](#beacon-key-encryption-context).
//# - `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
//#
//# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
//# the operation MUST use the `CiphertextBlob` as the wrapped Beacon Key.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#wrapped-branch-key-creation
//= type=exception
//# The operation MUST call [AWS KMS API GenerateDataKeyWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyWithoutPlaintext.html).
//# The call to AWS KMS GenerateDataKeyWithoutPlaintext MUST use the configured AWS KMS client to make the call.
//# The operation MUST call AWS KMS GenerateDataKeyWithoutPlaintext with a request constructed as follows:
//#
//# - `KeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
//# - `NumberOfBytes` MUST be 32.
//# - `EncryptionContext` MUST be the [DECRYPT_ONLY encryption context for branch keys](#decrypt_only-encryption-context).
//# - GenerateDataKeyWithoutPlaintext `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
//#
//# If the call to AWS KMS GenerateDataKeyWithoutPlaintext succeeds,
//# the operation MUST use the GenerateDataKeyWithoutPlaintext result `CiphertextBlob`
//# as the wrapped DECRYPT_ONLY Branch Key.
//#
//# The operation MUST call [AWS KMS API ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)
//# with a request constructed as follows:
//#
//# - `SourceEncryptionContext` MUST be the [DECRYPT_ONLY encryption context for branch keys](#decrypt_only-encryption-context).
//# - `SourceKeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
//# - `CiphertextBlob` MUST be the wrapped DECRYPT_ONLY Branch Key.
//# - ReEncrypt `GrantTokens` MUST be this keystore's [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
//# - `DestinationKeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
//# - `DestinationEncryptionContext` MUST be the [ACTIVE encryption context for branch keys](#active-encryption-context).
//#
//# If the call to AWS KMS ReEncrypt succeeds,
//# the operation MUST use the ReEncrypt result `CiphertextBlob`
//# as the wrapped ACTIVE Branch Key.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#active-encryption-context
//= type=exception
//# The ACTIVE branch key is a copy of the DECRYPT_ONLY with the same `version`.
//# It is structured slightly differently so that the active version can be accessed quickly.
//#
//# In addition to the [encryption context](#encryption-context):
//#
//# The ACTIVE encryption context value of the `type` attribute MUST equal to `"branch:ACTIVE"`.
//# The ACTIVE encryption context MUST have a `version` attribute.
//# The `version` attribute MUST store the branch key version formatted like `"branch:version:"` + `version`.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#decrypt-only-encryption-context
//= type=exception
//# In addition to the [encryption context](#encryption-context):
//#
//# The DECRYPT_ONLY encryption context MUST NOT have a `version` attribute.
//# The `type` attribute MUST stores the branch key version formatted like `"branch:version:"` + `version`.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#beacon-key-encryption-context
//= type=exception
//# In addition to the [encryption context](#encryption-context):
//#
//# The Beacon key encryption context value of the `type` attribute MUST equal to `"beacon:ACTIVE"`.
//# The Beacon key encryption context MUST NOT have a `version` attribute.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#versionkey
//= type=exception
//# - MUST supply a `branch-key-id`
//#
//# If the Keystore's KMS Configuration is `Discovery` or `MRDiscovery`,
//# this operation MUST immediately fail.
//#
//# VersionKey MUST first get the active version for the branch key from the keystore
//# by calling the configured [KeyStorage interface's](./key-store/key-storage.md#interface)
//# [GetEncryptedActiveBranchKey](./key-store/key-storage.md##getencryptedactivebranchkey)
//# using the `branch-key-id`.
//#
//# The `KmsArn` of the [EncryptedHierarchicalKey](./key-store/key-storage.md##encryptedhierarchicalkey)
//# MUST be [compatible with](#aws-key-arn-compatibility)
//# the configured `KMS ARN` in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
//#
//# Because the storage interface can be a custom implementation the key store needs to verify correctness.
//#
//# VersionKey MUST verify that the returned EncryptedHierarchicalKey MUST have the requested `branch-key-id`.
//# VersionKey MUST verify that the returned EncryptedHierarchicalKey is an ActiveHierarchicalSymmetricVersion.
//# VersionKey MUST verify that the returned EncryptedHierarchicalKey MUST have a logical table name equal to the configured logical table name.
//#
//# The `kms-arn` stored in the table MUST NOT change as a result of this operation,
//# even if the KeyStore is configured with a `KMS MRKey ARN` that does not exactly match the stored ARN.
//# If such were allowed, clients using non-MRK KeyStores might suddenly stop working.
//#
//# The [EncryptedHierarchicalKey](./key-store/key-storage.md##encryptedhierarchicalkey)
//# MUST be authenticated according to [authenticating a keystore item](#authenticating-an-encryptedhierarchicalkey).
//# If the item fails to authenticate this operation MUST fail.
//#
//# The wrapped Branch Keys, DECRYPT_ONLY and ACTIVE, MUST be created according to [Wrapped Branch Key Creation](#wrapped-branch-key-creation).
//#
//# If creation of the keys are successful,
//# then the key store MUST call the configured [KeyStorage interface's](./key-store/key-storage.md#interface)
//# [WriteNewEncryptedBranchKeyVersion](./key-store/key-storage.md##writenewencryptedbranchkeyversion)
//# with these 2 [EncryptedHierarchicalKeys](./key-store/key-storage.md##encryptedhierarchicalkey).
//#
//# If the [WriteNewEncryptedBranchKeyVersion](./key-store/key-storage.md##writenewencryptedbranchkeyversion) is successful,
//# this operation MUST return a successful response containing no additional data.
//# Otherwise, this operation MUST yield an error.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#authenticating-an-encryptedhierarchicalkey
//= type=exception
//# The operation MUST use the configured `KMS SDK Client` to authenticate the value of the keystore item.
//#
//# The operation MUST call [AWS KMS API ReEncrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html)
//# with a request constructed as follows:
//#
//# - `SourceEncryptionContext` MUST be the [encryption context](#encryption-context) of the EncryptedHierarchicalKey to be authenticated
//# - `SourceKeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
//# - `CiphertextBlob` MUST be the `CiphertextBlob` attribute value on the EncryptedHierarchicalKey to be authenticated
//# - `GrantTokens` MUST be the configured [grant tokens](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token).
//# - `DestinationKeyId` MUST be [compatible with](#aws-key-arn-compatibility) the configured KMS Key in the [AWS KMS Configuration](#aws-kms-configuration) for this keystore.
//# - `DestinationEncryptionContext` MUST be the [encryption context](#encryption-context) of the EncryptedHierarchicalKey to be authenticated

// Custom EC is only _added_ during construction.
// in all other cases, the EC will be associated with the existing records.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#custom-encryption-context
//= type=exception
//# If custom [encryption context](./structures.md#encryption-context-3)
//# is associated with the branch key these values MUST be added to the AWS KMS encryption context.
//# To avoid name collisions each added attribute from the custom [encryption context](./structures.md#encryption-context-3)
//# MUST be prefixed with `aws-crypto-ec:`.
//# Across all versions of a Branch Key, the custom encryption context MUST be equal.

//= aws-encryption-sdk-specification/framework/branch-key-store.md#keyschema
//= type=exception
//# The following KeySchema MUST be configured on the table:
//#
//# | AttributeName | KeyType   | Type |
//# | ------------- | --------- | ---- |
//# | branch-key-id | Partition | S    |
//# | type          | Sort      | S    |

//= aws-encryption-sdk-specification/framework/branch-key-store.md#getbeaconkey
//= type=exception
//# On invocation, the caller:
//#
//# - MUST supply a `branch-key-id`
//#
//# GetBeaconKey MUST get the requested beacon key from the keystore
//# by calling the configured [KeyStorage interface's](./key-store/key-storage.md#interface)
//# [GetEncryptedBeaconKey](./key-store/key-storage.md#getencryptedbeaconkey)
//# using the supplied `branch-key-id`.
//#
//# Because the storage interface can be a custom implementation the key store needs to verify correctness.
//#
//# GetBeaconKey MUST verify that the returned EncryptedHierarchicalKey MUST have the requested `branch-key-id`.
//# GetBeaconKey MUST verify that the returned EncryptedHierarchicalKey is an ActiveHierarchicalSymmetricBeacon.
//# GetBeaconKey MUST verify that the returned EncryptedHierarchicalKey MUST have a logical table name equal to the configured logical table name.
//#
//# The operation MUST decrypt the beacon key according to the [AWS KMS Branch Key Decryption](#aws-kms-branch-key-decryption) section.
//#
//# If the beacon key fails to decrypt, this operation MUST fail.
//#
//# This GetBeaconKey MUST construct [beacon key materials](./structures.md#beacon-key-materials) from the decrypted branch key material
//# and the `branchKeyId` from the returned `branch-key-id` field.
//#
//# This operation MUST return the constructed [beacon key materials](./structures.md#beacon-key-materials).
