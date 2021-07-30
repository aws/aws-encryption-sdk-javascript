// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AwsKmsMrkAwareSymmetricDiscoveryKeyringClass,
  AwsKmsMrkAwareSymmetricDiscoveryKeyringInput,
} from '@aws-crypto/kms-keyring'
import {
  KeyringNode,
  Newable,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'
import { KMS } from 'aws-sdk'

export type AwsKmsMrkAwareSymmetricDiscoveryKeyringNodeInput =
  AwsKmsMrkAwareSymmetricDiscoveryKeyringInput<KMS>

export const AwsKmsMrkAwareSymmetricDiscoveryKeyringNode =
  AwsKmsMrkAwareSymmetricDiscoveryKeyringClass<NodeAlgorithmSuite, KMS>(
    KeyringNode as Newable<KeyringNode>
  )
