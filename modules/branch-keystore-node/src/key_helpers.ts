// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KMSClient,
  GenerateDataKeyWithoutPlaintextCommand,
  ReEncryptCommand,
} from '@aws-sdk/client-kms'
import {
  DynamoDBClient,
  TransactWriteItemsCommand,
} from '@aws-sdk/client-dynamodb'
import { v4 } from 'uuid'
import { needs } from '@aws-crypto/material-management'
import { KmsKeyConfig } from './kms_config'
import {
  BRANCH_KEY_IDENTIFIER_FIELD,
  TYPE_FIELD,
  BRANCH_KEY_FIELD,
  KEY_CREATE_TIME_FIELD,
  HIERARCHY_VERSION_FIELD,
  TABLE_FIELD,
  BRANCH_KEY_TYPE_PREFIX,
  BRANCH_KEY_ACTIVE_TYPE,
  BRANCH_KEY_ACTIVE_VERSION_FIELD,
} from './constants'
import { IBranchKeyStorage } from './types'

interface VersionKeyParams {
  branchKeyIdentifier: string
  logicalKeyStoreName: string
  kmsConfiguration: Readonly<KmsKeyConfig>
  grantTokens?: ReadonlyArray<string>
  kmsClient: KMSClient
  ddbClient: DynamoDBClient
  ddbTableName: string
  storage: IBranchKeyStorage
}

//= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-and-beacon-key-creation
//# - `timestamp`: a timestamp for the current time.
//# This timestamp MUST be in ISO 8601 format in UTC, to microsecond precision
//# (e.g. "YYYY-MM-DDTHH:mm:ss.ssssssZ")
function getCurrentTimestamp(): string {
  const now = new Date()
  return now.toISOString().replace('Z', '000Z')
}

//= aws-encryption-sdk-specification/framework/branch-key-store.md#active-encryption-context
//# The ACTIVE encryption context value of the `type` attribute MUST equal to `"branch:ACTIVE"`.
//# The ACTIVE encryption context MUST have a `version` attribute.
//# The `version` attribute MUST store the branch key version formatted like `"branch:version:"` + `version`.
function buildActiveEncryptionContext(decryptOnlyContext: {
  [key: string]: string
}): { [key: string]: string } {
  const activeContext = { ...decryptOnlyContext }
  activeContext[BRANCH_KEY_ACTIVE_VERSION_FIELD] = activeContext[TYPE_FIELD]
  activeContext[TYPE_FIELD] = BRANCH_KEY_ACTIVE_TYPE
  return activeContext
}

function toAttributeMap(
  encryptionContext: { [key: string]: string },
  ciphertextBlob: Uint8Array
): { [key: string]: any } {
  const item: { [key: string]: any } = {}

  for (const [key, value] of Object.entries(encryptionContext)) {
    if (key === TABLE_FIELD) continue
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
    //# - "hierarchy-version" (N): 1
    if (key === HIERARCHY_VERSION_FIELD) {
      item[key] = { N: value }
    } else {
      item[key] = { S: value }
    }
  }

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#writing-branch-key-and-beacon-key-to-keystore
  //# - "enc" (B): the wrapped DECRYPT_ONLY Branch Key `CiphertextBlob` from the KMS operation
  item[BRANCH_KEY_FIELD] = { B: ciphertextBlob }

  return item
}

function getKmsKeyArn(
  kmsConfiguration: Readonly<KmsKeyConfig>
): string | undefined {
  return typeof kmsConfiguration._config === 'object' &&
    'identifier' in kmsConfiguration._config
    ? kmsConfiguration._config.identifier
    : typeof kmsConfiguration._config === 'object' &&
      'mrkIdentifier' in kmsConfiguration._config
    ? kmsConfiguration._config.mrkIdentifier
    : undefined
}

//= aws-encryption-sdk-specification/framework/branch-key-store.md#versionkey
//# On invocation, the caller:
//# - MUST supply a `branch-key-id`
export async function versionActiveBranchKey(
  params: VersionKeyParams
): Promise<void> {
  const {
    branchKeyIdentifier,
    logicalKeyStoreName,
    kmsConfiguration,
    grantTokens,
    kmsClient,
    ddbClient,
    ddbTableName,
    storage,
  } = params

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#versionkey
  //# VersionKey MUST first get the active version for the branch key from the keystore
  //# by calling AWS DDB `GetItem` using the `branch-key-id` as the Partition Key
  //# and `"branch:ACTIVE"` value as the Sort Key.
  const activeKey = await storage.getEncryptedActiveBranchKey(
    branchKeyIdentifier
  )

  needs(
    activeKey.branchKeyId === branchKeyIdentifier,
    'Unexpected branch key id'
  )

  needs(
    activeKey.encryptionContext[TABLE_FIELD] === logicalKeyStoreName,
    'Unexpected logical table name'
  )

  const kmsKeyArn = getKmsKeyArn(kmsConfiguration)
  needs(kmsKeyArn, 'KMS Key ARN is required')

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#versionkey
  //# The `kms-arn` field of DDB response item MUST be compatible with
  //# the configured `KMS ARN` in the AWS KMS Configuration for this keystore.
  const oldActiveContext = activeKey.encryptionContext

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#authenticating-a-keystore-item
  //# The operation MUST call AWS KMS API ReEncrypt with a request constructed as follows:
  //# - `SourceEncryptionContext` MUST be the encryption context constructed above
  //# - `SourceKeyId` MUST be compatible with the configured KMS Key in the AWS KMS Configuration for this keystore.
  //# - `CiphertextBlob` MUST be the `enc` attribute value on the AWS DDB response item
  //# - `GrantTokens` MUST be the configured grant tokens.
  //# - `DestinationKeyId` MUST be compatible with the configured KMS Key in the AWS KMS Configuration for this keystore.
  //# - `DestinationEncryptionContext` MUST be the encryption context constructed above
  await kmsClient.send(
    new ReEncryptCommand({
      SourceKeyId: kmsKeyArn,
      SourceEncryptionContext: oldActiveContext,
      CiphertextBlob: activeKey.ciphertextBlob,
      DestinationKeyId: kmsKeyArn,
      DestinationEncryptionContext: oldActiveContext,
      GrantTokens: grantTokens ? [...grantTokens] : undefined,
    })
  )

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#branch-key-and-beacon-key-creation
  //# - `version`: a new guid. This guid MUST be version 4 UUID
  const branchKeyVersion = v4()
  const timestamp = getCurrentTimestamp()

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#versionkey
  //# The wrapped Branch Keys, DECRYPT_ONLY and ACTIVE,
  //# MUST be created according to Wrapped Branch Key Creation.
  const decryptOnlyContext: { [key: string]: string } = {
    ...oldActiveContext,
    [TYPE_FIELD]: `${BRANCH_KEY_TYPE_PREFIX}${branchKeyVersion}`,
    [KEY_CREATE_TIME_FIELD]: timestamp,
  }
  delete decryptOnlyContext[BRANCH_KEY_ACTIVE_VERSION_FIELD]

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#wrapped-branch-key-creation
  //# The operation MUST call AWS KMS API GenerateDataKeyWithoutPlaintext
  //# with a request constructed as follows:
  //# - `KeyId` MUST be the configured `AWS KMS Key ARN` in the AWS KMS Configuration for this keystore.
  //# - `NumberOfBytes` MUST be 32.
  //# - `EncryptionContext` MUST be the DECRYPT_ONLY encryption context for branch keys.
  //# - GenerateDataKeyWithoutPlaintext `GrantTokens` MUST be this keystore's grant tokens.
  const decryptOnlyResponse = await kmsClient.send(
    new GenerateDataKeyWithoutPlaintextCommand({
      KeyId: kmsKeyArn,
      NumberOfBytes: 32,
      EncryptionContext: decryptOnlyContext,
      GrantTokens: grantTokens ? [...grantTokens] : undefined,
    })
  )

  needs(
    decryptOnlyResponse.CiphertextBlob,
    'Failed to generate new DECRYPT_ONLY branch key'
  )

  const newActiveContext = buildActiveEncryptionContext(decryptOnlyContext)

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#wrapped-branch-key-creation
  //# The operation MUST call AWS KMS API ReEncrypt with a request constructed as follows:
  //# - `SourceEncryptionContext` MUST be the DECRYPT_ONLY encryption context for branch keys.
  //# - `SourceKeyId` MUST be the configured `AWS KMS Key ARN` in the AWS KMS Configuration for this keystore.
  //# - `CiphertextBlob` MUST be the wrapped DECRYPT_ONLY Branch Key.
  //# - `DestinationKeyId` MUST be the configured `AWS KMS Key ARN` in the AWS KMS Configuration for this keystore.
  //# - `DestinationEncryptionContext` MUST be the ACTIVE encryption context for branch keys.
  const activeResponse = await kmsClient.send(
    new ReEncryptCommand({
      SourceKeyId: kmsKeyArn,
      SourceEncryptionContext: decryptOnlyContext,
      CiphertextBlob: decryptOnlyResponse.CiphertextBlob,
      DestinationKeyId: kmsKeyArn,
      DestinationEncryptionContext: newActiveContext,
      GrantTokens: grantTokens ? [...grantTokens] : undefined,
    })
  )

  needs(
    activeResponse.CiphertextBlob,
    'Failed to generate new ACTIVE branch key'
  )

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#versionkey
  //# To add the new branch key to the keystore,
  //# the operation MUST call Amazon DynamoDB API TransactWriteItems.
  //# The call to Amazon DynamoDB TransactWriteItems MUST use the configured Amazon DynamoDB Client to make the call.
  await ddbClient.send(
    new TransactWriteItemsCommand({
      TransactItems: [
        {
          //= aws-encryption-sdk-specification/framework/branch-key-store.md#versionkey
          //# - PUT:
          //#   - ConditionExpression: `attribute_not_exists(branch-key-id)`
          Put: {
            TableName: ddbTableName,
            Item: toAttributeMap(
              decryptOnlyContext,
              decryptOnlyResponse.CiphertextBlob
            ),
            ConditionExpression: 'attribute_not_exists(#bkid)',
            ExpressionAttributeNames: {
              '#bkid': BRANCH_KEY_IDENTIFIER_FIELD,
            },
          },
        },
        {
          //= aws-encryption-sdk-specification/framework/branch-key-store.md#versionkey
          //# - PUT:
          //#   - ConditionExpression: `attribute_exists(branch-key-id) AND enc = :encOld`
          //#   - ExpressionAttributeValues: `{":encOld" := DDB.AttributeValue.B(oldCiphertextBlob)}`
          Put: {
            TableName: ddbTableName,
            Item: toAttributeMap(
              newActiveContext,
              activeResponse.CiphertextBlob
            ),
            ConditionExpression: 'attribute_exists(#bkid) AND #enc = :encOld',
            ExpressionAttributeNames: {
              '#bkid': BRANCH_KEY_IDENTIFIER_FIELD,
              '#enc': BRANCH_KEY_FIELD,
            },
            ExpressionAttributeValues: {
              ':encOld': { B: activeKey.ciphertextBlob },
            },
          },
        },
      ],
    })
  )
}
