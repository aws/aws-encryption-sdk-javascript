// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { EncryptionContext } from '@aws-crypto/material-management'

//= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-supplier
//# The Branch Key Supplier is an interface containing the `GetBranchKeyId` operation.
//# This operation MUST take in an encryption context as input,
//# and return a branch key id (string) as output.
export interface BranchKeyIdSupplier {
  getBranchKeyId(encryptionContext: EncryptionContext): string
}

// type guard
export function isBranchKeyIdSupplier(
  supplier: any
): supplier is BranchKeyIdSupplier {
  return (
    typeof supplier === 'object' &&
    supplier !== null &&
    typeof supplier.getBranchKeyId === 'function'
  )
}
