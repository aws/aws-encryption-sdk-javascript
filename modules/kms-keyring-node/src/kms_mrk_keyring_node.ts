// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AwsKmsMrkAwareSymmetricKeyringClass,
  AwsKmsMrkAwareSymmetricKeyringInput,
} from '@aws-crypto/kms-keyring'
import {
  KeyringNode,
  Newable,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'
import { KMS } from 'aws-sdk'

export type AwsKmsMrkAwareSymmetricKeyringNodeInput =
  AwsKmsMrkAwareSymmetricKeyringInput<KMS>

export const AwsKmsMrkAwareSymmetricKeyringNode =
  AwsKmsMrkAwareSymmetricKeyringClass<NodeAlgorithmSuite, KMS>(
    KeyringNode as Newable<KeyringNode>
  )
