// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AwsKmsMrkAwareSymmetricDiscoveryKeyringClass,
  AwsKmsMrkAwareSymmetricDiscoveryKeyringInput,
  AwsEsdkKMSInterface,
} from '@aws-crypto/kms-keyring'
import {
  KeyringNode,
  Newable,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'

export type AwsKmsMrkAwareSymmetricDiscoveryKeyringNodeInput =
  AwsKmsMrkAwareSymmetricDiscoveryKeyringInput<AwsEsdkKMSInterface>

export const AwsKmsMrkAwareSymmetricDiscoveryKeyringNode =
  AwsKmsMrkAwareSymmetricDiscoveryKeyringClass<NodeAlgorithmSuite, AwsEsdkKMSInterface>(
    KeyringNode as Newable<KeyringNode>
  )
