// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CommitmentPolicy } from '@aws-crypto/material-management-browser'
import { buildDecrypt } from './decrypt_client'
export { DecryptResult } from './decrypt'
export { MessageHeader } from '@aws-crypto/serialize'
/** @deprecated Use `buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. */
export const { decrypt } = buildDecrypt(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)
export { buildDecrypt }
