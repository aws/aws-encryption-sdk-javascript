// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AwsKmsMrkAwareSymmetricKeyringClass,
  AwsKmsMrkAwareSymmetricKeyringInput,
  AwsEsdkKMSInterface,
} from '@aws-crypto/kms-keyring'
import {
  KeyringNode,
  Newable,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'

export type AwsKmsMrkAwareSymmetricKeyringNodeInput =
  AwsKmsMrkAwareSymmetricKeyringInput<AwsEsdkKMSInterface>

export const AwsKmsMrkAwareSymmetricKeyringNode =
  AwsKmsMrkAwareSymmetricKeyringClass<NodeAlgorithmSuite, AwsEsdkKMSInterface>(
    KeyringNode as Newable<KeyringNode>
  )
