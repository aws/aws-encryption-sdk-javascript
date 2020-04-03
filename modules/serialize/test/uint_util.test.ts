// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { uInt8, uInt16BE, uInt32BE } from '../src/uint_util'

describe('uInt8', () => {
  it('Precondition: Number must be 0-(2^8 - 1).', () => {
    expect(() => uInt8(-1)).to.throw()
    expect(() => uInt8(2 ** 8)).to.throw()
  })
})

describe('uInt16BE', () => {
  it('Precondition: Number must be 0-(2^16 - 1).', () => {
    expect(() => uInt16BE(-1)).to.throw()
    expect(() => uInt16BE(2 ** 16)).to.throw()
  })
})

describe('uInt32BE', () => {
  it('Precondition: Number must be 0-(2^32 - 1).', () => {
    expect(() => uInt32BE(-1)).to.throw()
    expect(() => uInt32BE(2 ** 32)).to.throw()
  })
})
