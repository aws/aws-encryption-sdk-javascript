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
import { decodeNamedCurves } from '../src/ecc_decode'
import { encodeNamedCurves } from '../src/ecc_encode'

const prime256v1PublicFixture = [ 4,
  54, 131, 184, 190, 94, 145, 250, 132, 150, 193,
  178, 150, 190, 22, 22, 11, 201, 60, 9, 53,
  128, 68, 120, 118, 83, 106, 52, 226, 143, 155,
  120, 178, 217, 246, 201, 43, 28, 98, 154, 24,
  59, 251, 229, 162, 89, 161, 79, 81, 23, 238,
  208, 108, 15, 209, 56, 91, 237, 38, 60, 72,
  98, 181, 219, 196 ]

const prime256v1CompressedFixture = [ 2,
  54, 131, 184, 190, 94, 145, 250, 132, 150, 193,
  178, 150, 190, 22, 22, 11, 201, 60, 9, 53,
  128, 68, 120, 118, 83, 106, 52, 226, 143, 155,
  120, 178 ]

describe('ecc', () => {
  it('encodeNamedCurves.prime256v1', () => {
    const publicKey = new Uint8Array(prime256v1PublicFixture)
    const compressPoint = encodeNamedCurves.prime256v1(publicKey)
    expect(compressPoint).to.deep.equal(new Uint8Array(prime256v1CompressedFixture))
  })

  it('Precondition: publicKey must be the right length.', () => {
    const publicKey = new Uint8Array(5)
    expect(() => encodeNamedCurves.prime256v1(publicKey)).to.throw()
  })

  it('encodeNamedCurves.prime256v1', () => {
    const compressPoint = new Uint8Array(prime256v1CompressedFixture)
    const publicKey = decodeNamedCurves.prime256v1(compressPoint)
    expect(publicKey).to.deep.equal(new Uint8Array(prime256v1PublicFixture))
  })

  it('Precondition: compressedPoint must be the correct length.', () => {
    const compressPoint = new Uint8Array(5)
    expect(() => decodeNamedCurves.prime256v1(compressPoint)).to.throw()
  })
})
