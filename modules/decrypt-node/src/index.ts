// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CommitmentPolicy } from '@aws-crypto/material-management-node'
import { buildDecrypt } from './decrypt_client'
export { MessageHeader } from '@aws-crypto/serialize'
import { deprecate } from 'util'
const { decrypt: decryptTmp, decryptStream: decryptStreamTmp } = buildDecrypt(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)
/** @deprecated Use `buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. */
const decrypt = deprecate(
  decryptTmp,
  'Use `buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html'
)
/** @deprecated Use `buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. */
const decryptStream = deprecate(
  decryptStreamTmp,
  'Use `buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html'
)
export { decrypt, decryptStream }
export { buildDecrypt }
