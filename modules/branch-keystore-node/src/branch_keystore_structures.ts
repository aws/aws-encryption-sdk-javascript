// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  BRANCH_KEY_ACTIVE_VERSION_FIELD,
  BRANCH_KEY_FIELD,
  BRANCH_KEY_IDENTIFIER_FIELD,
  HIERARCHY_VERSION_FIELD,
  KEY_CREATE_TIME_FIELD,
  KMS_FIELD,
  TYPE_FIELD,
} from './constants'

// a nicer (easier-to-understand) type alias
export type BranchKeyItem = Record<string, any>

export interface BranchKeyRecord {
  [BRANCH_KEY_IDENTIFIER_FIELD]: string
  [TYPE_FIELD]: string
  [BRANCH_KEY_ACTIVE_VERSION_FIELD]?: string
  [BRANCH_KEY_FIELD]: Uint8Array
  [KMS_FIELD]: string
  [KEY_CREATE_TIME_FIELD]: string
  [HIERARCHY_VERSION_FIELD]: number
}
