// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CommitmentPolicy } from '@aws-crypto/material-management-node'
import { buildEncrypt } from './encrypt_client'
export { MessageHeader } from '@aws-crypto/serialize'

import { deprecate } from 'util'
const { encrypt: encryptTmp, encryptStream: encryptStreamTmp } = buildEncrypt(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)
/** @deprecated Use `buildEncrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. */
const encrypt = deprecate(
  encryptTmp,
  'Use `buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html'
)
/** @deprecated Use `buildEncrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. */
const encryptStream = deprecate(
  encryptStreamTmp,
  'Use `buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)` for migration. See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/troubleshooting-migration.html'
)
export { encrypt, encryptStream }

export { buildEncrypt }
