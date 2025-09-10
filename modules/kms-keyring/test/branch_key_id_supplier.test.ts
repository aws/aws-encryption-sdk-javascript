// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { EncryptionContext } from '@aws-crypto/material-management'
import { BranchKeyIdSupplier, isBranchKeyIdSupplier } from '../src'
import { expect } from 'chai'

describe('Branch key id supplier', () => {
  //= aws-encryption-sdk-specification/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-supplier
  //= type=test
  //# The Branch Key Supplier is an interface containing the `GetBranchKeyId` operation.
  //# This operation MUST take in an encryption context as input,
  //# and return a branch key id (string) as output.
  it('Can implement the interface', () => {
    class Example implements BranchKeyIdSupplier {
      getBranchKeyId(encryptionContext: EncryptionContext): string {
        return '' in encryptionContext ? '' : ''
      }
    }

    expect(new Example().getBranchKeyId({})).to.equal('')
  })

  it('Type guard', () => {
    expect(isBranchKeyIdSupplier(undefined as any)).to.be.false
    expect(isBranchKeyIdSupplier(null as any)).to.be.false
    expect(isBranchKeyIdSupplier({} as any)).to.be.false
  })
})
