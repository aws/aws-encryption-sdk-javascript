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
import { concatBuffers } from '../src/concat_buffers'
import { Buffer } from 'buffer'

describe('concatBuffers', () => {
  it('should concatenate simple Uint8Array', () => {
    const buff = Array(5).fill(1).map((_, i) => new Uint8Array([i]))
    const test = concatBuffers(...buff)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(5)
    expect(test).to.deep.equal(new Uint8Array([0, 1, 2, 3, 4]))
  })

  it('should concatenate simple ArrayBuffer', () => {
    const buff = Array(5).fill(1).map((_, i) => new Uint8Array([i]).buffer)
    const test = concatBuffers(...buff)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(5)
    expect(test).to.deep.equal(new Uint8Array([0, 1, 2, 3, 4]))
  })

  it('should concatenate simple Node Buffer', () => {
    const buff = Array(5).fill(1).map((_, i) => Buffer.alloc(1, i))
    const test = concatBuffers(...buff)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(5)
    expect(test).to.deep.equal(new Uint8Array([0, 1, 2, 3, 4]))
  })
})
