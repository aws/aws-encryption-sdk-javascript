// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { concatBuffers } from '../src/concat_buffers'
import { Buffer } from 'buffer'

describe('concatBuffers', () => {
  it('should concatenate simple Uint8Array', () => {
    const buff = Array(5)
      .fill(1)
      .map((_, i) => new Uint8Array([i]))
    const test = concatBuffers(...buff)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(5)
    expect(test).to.deep.equal(new Uint8Array([0, 1, 2, 3, 4]))
  })

  it('should concatenate simple ArrayBuffer', () => {
    const buff = Array(5)
      .fill(1)
      .map((_, i) => new Uint8Array([i]).buffer)
    const test = concatBuffers(...buff)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(5)
    expect(test).to.deep.equal(new Uint8Array([0, 1, 2, 3, 4]))
  })

  it('should concatenate simple Node Buffer', () => {
    const buff = Array(5)
      .fill(1)
      .map((_, i) => Buffer.alloc(1, i))
    const test = concatBuffers(...buff)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(5)
    expect(test).to.deep.equal(new Uint8Array([0, 1, 2, 3, 4]))
  })
})
