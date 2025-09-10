// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const PARTITION_KEY = 'branch-key-id'
export const SORT_KEY = 'type'
export const TABLE_FIELD = 'tablename'
export const CUSTOM_ENCRYPTION_CONTEXT_FIELD_PREFIX = 'aws-crypto-ec:'
export const BRANCH_KEY_IDENTIFIER_FIELD = PARTITION_KEY
export const TYPE_FIELD = SORT_KEY
export const KEY_CREATE_TIME_FIELD = 'create-time'
export const HIERARCHY_VERSION_FIELD = 'hierarchy-version'
export const KMS_FIELD = 'kms-arn'
export const BRANCH_KEY_FIELD = 'enc'
export const BRANCH_KEY_ACTIVE_VERSION_FIELD = 'version'
export const BRANCH_KEY_TYPE_PREFIX = 'branch:version:'
export const BRANCH_KEY_ACTIVE_TYPE = 'branch:ACTIVE'
export const BEACON_KEY_TYPE_VALUE = 'beacon:ACTIVE'
export const POTENTIAL_BRANCH_KEY_RECORD_FIELDS = [
  BRANCH_KEY_IDENTIFIER_FIELD,
  TYPE_FIELD,
  KEY_CREATE_TIME_FIELD,
  HIERARCHY_VERSION_FIELD,
  KMS_FIELD,
  BRANCH_KEY_FIELD,
  BRANCH_KEY_ACTIVE_VERSION_FIELD,
]
export const KMS_CLIENT_USER_AGENT = 'aws-kms-hierarchy'
