// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { CommitmentPolicy } from '@aws-crypto/material-management-node'
import { buildEncrypt } from '../src/index'

chai.use(chaiAsPromised)
const { expect } = chai

describe('buildEncrypt', () => {
  it('can build a client', () => {
    const test = buildEncrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    expect(test).to.have.property('encrypt').and.to.be.a('function')
    expect(test).to.have.property('encryptStream').and.to.be.a('function')
  })

  it('Precondition: node buildEncrypt needs a valid commitmentPolicy.', () => {
    expect(() => buildEncrypt({} as any)).to.throw('Invalid commitment policy.')
  })
})
