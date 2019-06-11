/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import { compare } from '../src/portable_compare'

describe('compare', () => {
  const a = new Uint8Array([0, 0])
  const b = new Uint8Array([1, 0])
  const c = new Uint8Array([0, 1])
  const d = new Uint8Array([1])
  const e = new Uint8Array([0])
  it('a == a', () => {
    expect(compare(a, a)).to.equal(0)
  })
  it('b > a', () => {
    expect(compare(b, a)).to.equal(1)
  })
  it('a < b', () => {
    expect(compare(a, b)).to.equal(-1)
  })
  it('c > a', () => {
    expect(compare(c, a)).to.equal(1)
  })
  it('a < c', () => {
    expect(compare(a, c)).to.equal(-1)
  })
  it('d > a', () => {
    expect(compare(d, a)).to.equal(1)
  })
  it('a < d', () => {
    expect(compare(a, d)).to.equal(-1)
  })
  it('b > d', () => {
    expect(compare(b, d)).to.equal(1)
  })
  it('d < b', () => {
    expect(compare(d, b)).to.equal(-1)
  })
  it('a > e', () => {
    expect(compare(a, e)).to.equal(1)
  })
  it('e < a', () => {
    expect(compare(e, a)).to.equal(-1)
  })
})
