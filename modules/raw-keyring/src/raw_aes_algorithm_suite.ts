/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management'

export type WrappingSuiteIdentifier = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16 |
AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16 |
AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16

type RawAesWrappingNames = 'AES128_GCM_IV12_TAG16_NO_PADDING'| 'AES192_GCM_IV12_TAG16_NO_PADDING'| 'AES256_GCM_IV12_TAG16_NO_PADDING'

const AES128_GCM_IV12_TAG16_NO_PADDING: AlgorithmSuiteIdentifier = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
const AES192_GCM_IV12_TAG16_NO_PADDING: AlgorithmSuiteIdentifier = AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16
const AES256_GCM_IV12_TAG16_NO_PADDING: AlgorithmSuiteIdentifier = AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16
export const RawAesWrappingSuiteIdentifier: {[K in RawAesWrappingNames|WrappingSuiteIdentifier]: WrappingSuiteIdentifier} = Object.freeze({
  AES128_GCM_IV12_TAG16_NO_PADDING,
  AES192_GCM_IV12_TAG16_NO_PADDING,
  AES256_GCM_IV12_TAG16_NO_PADDING,
  // Adding reverse lookup to support checking supported suites
  [AES128_GCM_IV12_TAG16_NO_PADDING]: AES128_GCM_IV12_TAG16_NO_PADDING,
  [AES192_GCM_IV12_TAG16_NO_PADDING]: AES192_GCM_IV12_TAG16_NO_PADDING,
  [AES256_GCM_IV12_TAG16_NO_PADDING]: AES256_GCM_IV12_TAG16_NO_PADDING
})
