// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  getAwsKmsMrkAwareDiscoveryMultiKeyringBuilder,
  KmsClientSupplier,
} from '@aws-crypto/kms-keyring'
import {
  MultiKeyringNode,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management'
import { getKmsClient } from '.'
import { AwsKmsMrkAwareSymmetricDiscoveryKeyringNode } from './kms_mrk_discovery_keyring_node'
import { KMS } from 'aws-sdk'

export interface AwsKmsMrkAwareDiscoveryMultiKeyringNodeInput {
  regions: string[]
  clientProvider?: KmsClientSupplier<KMS>
  discoveryFilter?: Readonly<{
    accountIDs: readonly string[]
    partition: string
  }>
  grantTokens?: string[]
}

export const buildAwsKmsMrkAwareDiscoveryMultiKeyringNode =
  getAwsKmsMrkAwareDiscoveryMultiKeyringBuilder<NodeAlgorithmSuite, KMS>(
    AwsKmsMrkAwareSymmetricDiscoveryKeyringNode,
    MultiKeyringNode,
    getKmsClient
  )
