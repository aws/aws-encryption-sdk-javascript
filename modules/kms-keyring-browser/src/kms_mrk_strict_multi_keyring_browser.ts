// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { getAwsKmsMrkAwareStrictMultiKeyringBuilder, AwsEsdkKMSInterface } from '@aws-crypto/kms-keyring'
import {
  MultiKeyringWebCrypto,
  WebCryptoAlgorithmSuite,
} from '@aws-crypto/material-management-browser'
import { getKmsClient } from '.'
import { AwsKmsMrkAwareSymmetricKeyringBrowser } from './kms_mrk_keyring_browser'

export const buildAwsKmsMrkAwareStrictMultiKeyringBrowser =
  getAwsKmsMrkAwareStrictMultiKeyringBuilder<WebCryptoAlgorithmSuite, AwsEsdkKMSInterface>(
    AwsKmsMrkAwareSymmetricKeyringBrowser,
    MultiKeyringWebCrypto,
    getKmsClient
  )
