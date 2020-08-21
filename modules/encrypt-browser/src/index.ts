// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CommitmentPolicy } from '@aws-crypto/material-management-browser'
import { buildEncrypt } from './encrypt_client'
export { MessageHeader } from '@aws-crypto/serialize'

/** @deprecated Use `buildEncrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. */
export const { encrypt } = buildEncrypt(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)

export { buildEncrypt }
