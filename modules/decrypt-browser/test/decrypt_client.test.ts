// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { CommitmentPolicy } from '@aws-crypto/material-management-node'
import { buildDecrypt } from '../src/index'

chai.use(chaiAsPromised)
const { expect } = chai

describe('buildDecrypt', () => {
  it('can build a client', () => {
    const test = buildDecrypt(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
    expect(test).to.have.property('decrypt').and.to.be.a('function')
  })

  it('Precondition: browser buildDecrypt needs a valid commitmentPolicy.', () => {
    expect(() => buildDecrypt({} as any)).to.throw('Invalid commitment policy.')
  })
})
