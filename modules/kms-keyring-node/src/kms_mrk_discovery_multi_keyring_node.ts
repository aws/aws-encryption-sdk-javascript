// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  getAwsKmsMrkAwareDiscoveryMultiKeyringBuilder,
  KmsClientSupplier,
  AwsEsdkKMSInterface,
} from '@aws-crypto/kms-keyring'
import {
  MultiKeyringNode,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management'
import { getKmsClient } from '.'
import { AwsKmsMrkAwareSymmetricDiscoveryKeyringNode } from './kms_mrk_discovery_keyring_node'

export interface AwsKmsMrkAwareDiscoveryMultiKeyringNodeInput {
  regions: string[]
  clientProvider?: KmsClientSupplier<AwsEsdkKMSInterface>
  discoveryFilter?: Readonly<{
    accountIDs: readonly string[]
    partition: string
  }>
  grantTokens?: string[]
}

export const buildAwsKmsMrkAwareDiscoveryMultiKeyringNode =
  getAwsKmsMrkAwareDiscoveryMultiKeyringBuilder<
    NodeAlgorithmSuite,
    AwsEsdkKMSInterface
  >(AwsKmsMrkAwareSymmetricDiscoveryKeyringNode, MultiKeyringNode, getKmsClient)
