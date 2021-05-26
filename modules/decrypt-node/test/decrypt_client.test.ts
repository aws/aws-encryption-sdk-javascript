// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
// @ts-ignore
import chaiAsPromised from 'chai-as-promised'
import { CommitmentPolicy } from '@aws-crypto/material-management-node'
import { buildDecrypt } from '../src/index'

chai.use(chaiAsPromised)
const { expect } = chai

describe('buildDecrypt', () => {
  it('can build a client with a commitment policy', () => {
    const test = buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    expect(test).to.have.property('decrypt').and.to.be.a('function')
    expect(test).to.have.property('decryptStream').and.to.be.a('function')
    expect(test)
      .to.have.property('decryptUnsignedMessageStream')
      .and.to.be.a('function')
  })

  it('Precondition: node buildDecrypt needs a valid commitmentPolicy.', () => {
    expect(() => buildDecrypt('BAD_POLICY' as any)).to.throw(
      'Invalid commitment policy.'
    )
  })

  it('Precondition: node buildDecrypt needs a valid maxEncryptedDataKeys.', () => {
    expect(() =>
      buildDecrypt({
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        maxEncryptedDataKeys: 0,
      })
    ).to.throw('Invalid maxEncryptedDataKeys value.')
    expect(() =>
      buildDecrypt({
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
        maxEncryptedDataKeys: -1,
      })
    ).to.throw('Invalid maxEncryptedDataKeys value.')
  })
})
