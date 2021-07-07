// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { getAwsKmsMrkAwareStrictMultiKeyringBuilder } from '@aws-crypto/kms-keyring'
import { KmsClientSupplier } from '@aws-crypto/kms-keyring'
import {
  MultiKeyringNode,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management'
import { getKmsClient } from '.'
import { AwsKmsMrkAwareSymmetricKeyringNode } from './kms_mrk_keyring_node'
import { KMS } from 'aws-sdk'

export interface AwsKmsMrkAwareStrictMultiKeyringNodeInput {
  clientProvider?: KmsClientSupplier<KMS>
  generatorKeyId?: string
  keyIds?: string[]
  grantTokens?: string[]
}

export const buildAwsKmsMrkAwareStrictMultiKeyringNode =
  getAwsKmsMrkAwareStrictMultiKeyringBuilder<NodeAlgorithmSuite, KMS>(
    AwsKmsMrkAwareSymmetricKeyringNode,
    MultiKeyringNode,
    getKmsClient
  )
