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
import BN from 'bn.js'
import { randomRangeBNjs } from '../src/random_range'

describe('randomRangeBNjs preconditions', () => {
  it('Precondition: Needs to be a BN.js or I can not parse it.', () => {
    expect(() => randomRangeBNjs(<any>'not BN')).to.throw()
    expect(() => randomRangeBNjs(<any>15)).to.throw()
  })
  it('Precondition: bound must be positive, 0 is neither positive nor negative', () => {
    expect(() => randomRangeBNjs(new BN(-1))).to.throw()
    expect(() => randomRangeBNjs(new BN(0))).to.throw()
  })
  it('bruteForceMassiveIgnorance', () => {
    // Check the first few number...
    ;[1, 2, 3, 4, 5, 6, 7, 8].map(bruteForceMassiveIgnorance)
    // Check the Byte Boundary
    ;[255, 256, 257].map(bruteForceMassiveIgnorance)
  })
})

const bruteForceAttempts = 5000
/** This test generates `bruteForceAttempts` number of random values (5000)
 * within the range and checks to ensure that all numbers in the range are generated
 * and no numbers outside of the range are generated.
 * This is done to ensure that there are no off-by-one errors
 * or simple math mistakes at boundary conditions.
 * While this test may fail due to a number not being generated,
 * the odds of that are sufficiently low (approximately 1 in 2^28) that I accept them.
 * This test does not check for even distribution.
 * @param bound BN that is the bound for the test.
 */
function bruteForceMassiveIgnorance (bound: number) {
  const range = Array(bound).fill(-1).map((_n, i) => i)
  const max = bound - 1
  const test = fill(new BN(bound))
  expect(test).lengthOf(bruteForceAttempts)
  expect(Math.min(...test)).to.equal(0)
  expect(Math.max(...test)).to.equal(max)
  expect(range.map(n => test.includes(n)).includes(false)).to.equal(false)
}

function fill (bound: BN) {
  return Array(bruteForceAttempts)
    .fill(-1)
    .map(() => randomRangeBNjs(bound))
    .map(bn => bn.toNumber())
}
