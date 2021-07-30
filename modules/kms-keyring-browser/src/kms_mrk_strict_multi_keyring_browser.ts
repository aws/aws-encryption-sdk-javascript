// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { getAwsKmsMrkAwareStrictMultiKeyringBuilder } from '@aws-crypto/kms-keyring'
import {
  MultiKeyringWebCrypto,
  WebCryptoAlgorithmSuite,
} from '@aws-crypto/material-management-browser'
import { getKmsClient } from '.'
import { AwsKmsMrkAwareSymmetricKeyringBrowser } from './kms_mrk_keyring_browser'
import { KMS } from 'aws-sdk'

export const buildAwsKmsMrkAwareStrictMultiKeyringBrowser =
  getAwsKmsMrkAwareStrictMultiKeyringBuilder<WebCryptoAlgorithmSuite, KMS>(
    AwsKmsMrkAwareSymmetricKeyringBrowser,
    MultiKeyringWebCrypto,
    getKmsClient
  )
