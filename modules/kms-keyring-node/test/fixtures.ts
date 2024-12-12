// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  BranchKeyStoreNode,
} from '@aws-crypto/branch-keystore-node'
import {
  AlgorithmSuiteIdentifier,
  EncryptionContext,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management'

export const DDB_TABLE_NAME = 'KeyStoreDdbTable'
export const LOGICAL_KEYSTORE_NAME = DDB_TABLE_NAME
export const BRANCH_KEY_ID = '75789115-1deb-4fe3-a2ec-be9e885d1945'
export const BRANCH_KEY_ACTIVE_VERSION = 'fed7ad33-0774-4f97-aa5e-6c766fc8af9f'
export const BRANCH_KEY_ID_WITH_EC = '4bb57643-07c1-419e-92ad-0df0df149d7c'

export const KEY_ARN =
  'arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'

export const TEST_ESDK_ALG_SUITE_ID =
  AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16
export const TEST_ESDK_ALG_SUITE = new NodeAlgorithmSuite(
  TEST_ESDK_ALG_SUITE_ID
)
export const TTL = 1 * 60000 * 10
export const KEYSTORE = new BranchKeyStoreNode({
  storage: {ddbTableName: DDB_TABLE_NAME},
  logicalKeyStoreName: LOGICAL_KEYSTORE_NAME,
  kmsConfiguration: { identifier: KEY_ARN },
})

// Constants for TestBranchKeySupplier
export const BRANCH_KEY = 'branchKey'
export const CASE_A = 'caseA'
export const CASE_B = 'caseB'
export const BRANCH_KEY_ID_A = BRANCH_KEY_ID
export const BRANCH_KEY_ID_B = BRANCH_KEY_ID_WITH_EC
export const DEFAULT_EC: EncryptionContext = { keyA: 'valA' }
export const EC_A: EncryptionContext = { [BRANCH_KEY]: CASE_A }
export const EC_B: EncryptionContext = { [BRANCH_KEY]: CASE_B }

export const ALG_SUITE_IDS = [
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16,
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
  AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16,
  AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16,
  AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256,
  AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
  AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
  AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
]
export const ALG_SUITES = ALG_SUITE_IDS.map((id) => new NodeAlgorithmSuite(id))
