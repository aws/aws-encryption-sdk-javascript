// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { getAwsKmsMrkAwareStrictMultiKeyringBuilder, AwsEsdkKMSInterface } from '@aws-crypto/kms-keyring'
import { KmsClientSupplier } from '@aws-crypto/kms-keyring'
import {
  MultiKeyringNode,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'
import { getKmsClient } from '.'
import { AwsKmsMrkAwareSymmetricKeyringNode } from './kms_mrk_keyring_node'

export interface AwsKmsMrkAwareStrictMultiKeyringNodeInput {
  clientProvider?: KmsClientSupplier<AwsEsdkKMSInterface>
  generatorKeyId?: string
  keyIds?: string[]
  grantTokens?: string[]
}

export const buildAwsKmsMrkAwareStrictMultiKeyringNode =
  getAwsKmsMrkAwareStrictMultiKeyringBuilder<NodeAlgorithmSuite, AwsEsdkKMSInterface>(
    AwsKmsMrkAwareSymmetricKeyringNode,
    MultiKeyringNode,
    getKmsClient
  )
