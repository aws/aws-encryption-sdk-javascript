// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export * from '@aws-crypto/encrypt-browser'
export * from '@aws-crypto/decrypt-browser'
export * from '@aws-crypto/material-management-browser'
export * from '@aws-crypto/caching-materials-manager-browser'
export * from '@aws-crypto/kms-keyring-browser'
export * from '@aws-crypto/raw-aes-keyring-browser'
export * from '@aws-crypto/raw-rsa-keyring-browser'
export * from '@aws-crypto/web-crypto-backend'

import {
  CommitmentPolicy,
  ClientOptions,
} from '@aws-crypto/material-management-browser'

import { buildEncrypt } from '@aws-crypto/encrypt-browser'
import { buildDecrypt } from '@aws-crypto/decrypt-browser'

export function buildClient(
  options?: CommitmentPolicy | ClientOptions
): ReturnType<typeof buildEncrypt> & ReturnType<typeof buildDecrypt> {
  return {
    ...buildEncrypt(options),
    ...buildDecrypt(options),
  }
}
