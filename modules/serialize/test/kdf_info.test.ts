// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { kdfInfo } from '../src/kdf_info'
import { Buffer } from 'buffer'

describe('kdfInfo', () => {
  it('should produce appropriate info', () => {
    const messageId = Buffer.alloc(16, 1)
    const test = kdfInfo(0x0014, messageId)

    expect(test).to.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(18)
    expect(test).to.deep.equal(new Uint8Array([0, 20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]))
  })
})
