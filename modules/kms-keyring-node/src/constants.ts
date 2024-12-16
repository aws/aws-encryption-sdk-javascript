// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { KeyringTraceFlag } from '@aws-crypto/material-management'

export const ACTIVE_AS_BYTES = Buffer.from('ACTIVE', 'utf-8')
export const CACHE_ENTRY_ID_DIGEST_ALGORITHM = 'sha384'
export const KDF_DIGEST_ALGORITHM_SHA_256 = 'sha256'
export const ENCRYPT_FLAGS =
  KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY |
  KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
export const DECRYPT_FLAGS =
  KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY |
  KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX
export const PROVIDER_ID_HIERARCHY = 'aws-kms-hierarchy'
export const PROVIDER_ID_HIERARCHY_AS_BYTES = Buffer.from(
  PROVIDER_ID_HIERARCHY,
  'utf-8'
)
export const DERIVED_BRANCH_KEY_LENGTH = 32
// export const CACHE_ENTRY_ID_LENGTH = 32
export const KEY_DERIVATION_LABEL = Buffer.from(PROVIDER_ID_HIERARCHY, 'utf-8')
export const CIPHERTEXT_STRUCTURE = {
  saltLength: 16,
  ivLength: 12,
  branchKeyVersionCompressedLength: 16,
  // Encrypted Key is of variable length
  authTagLength: 16,
}
