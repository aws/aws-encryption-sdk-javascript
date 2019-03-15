/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
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
