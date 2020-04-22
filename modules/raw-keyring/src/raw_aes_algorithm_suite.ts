// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management'

export type WrappingSuiteIdentifier =
  | AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
  | AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16
  | AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16

type RawAesWrappingNames =
  | 'AES128_GCM_IV12_TAG16_NO_PADDING'
  | 'AES192_GCM_IV12_TAG16_NO_PADDING'
  | 'AES256_GCM_IV12_TAG16_NO_PADDING'

const AES128_GCM_IV12_TAG16_NO_PADDING: AlgorithmSuiteIdentifier =
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
const AES192_GCM_IV12_TAG16_NO_PADDING: AlgorithmSuiteIdentifier =
  AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16
const AES256_GCM_IV12_TAG16_NO_PADDING: AlgorithmSuiteIdentifier =
  AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16
export const RawAesWrappingSuiteIdentifier: {
  [K in RawAesWrappingNames | WrappingSuiteIdentifier]: WrappingSuiteIdentifier
} = Object.freeze({
  AES128_GCM_IV12_TAG16_NO_PADDING,
  AES192_GCM_IV12_TAG16_NO_PADDING,
  AES256_GCM_IV12_TAG16_NO_PADDING,
  // Adding reverse lookup to support checking supported suites
  [AES128_GCM_IV12_TAG16_NO_PADDING]: AES128_GCM_IV12_TAG16_NO_PADDING,
  [AES192_GCM_IV12_TAG16_NO_PADDING]: AES192_GCM_IV12_TAG16_NO_PADDING,
  [AES256_GCM_IV12_TAG16_NO_PADDING]: AES256_GCM_IV12_TAG16_NO_PADDING,
})
