// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { decodeNamedCurves } from '../src/ecc_decode'
import { encodeNamedCurves } from '../src/ecc_encode'

const prime256v1PublicFixture = [
  4, 54, 131, 184, 190, 94, 145, 250, 132, 150, 193, 178, 150, 190, 22, 22, 11,
  201, 60, 9, 53, 128, 68, 120, 118, 83, 106, 52, 226, 143, 155, 120, 178, 217,
  246, 201, 43, 28, 98, 154, 24, 59, 251, 229, 162, 89, 161, 79, 81, 23, 238,
  208, 108, 15, 209, 56, 91, 237, 38, 60, 72, 98, 181, 219, 196,
]

const prime256v1CompressedFixture = [
  2, 54, 131, 184, 190, 94, 145, 250, 132, 150, 193, 178, 150, 190, 22, 22, 11,
  201, 60, 9, 53, 128, 68, 120, 118, 83, 106, 52, 226, 143, 155, 120, 178,
]

const secp384r1PublicFixture = [
  4, 207, 62, 215, 143, 116, 128, 174, 103, 1, 81, 127, 212, 163, 19, 165, 220,
  74, 144, 26, 59, 87, 0, 214, 47, 66, 73, 152, 227, 196, 81, 14, 28, 58, 221,
  178, 63, 150, 119, 62, 195, 99, 63, 60, 42, 223, 207, 28, 65, 180, 143, 190,
  5, 150, 247, 225, 240, 153, 150, 119, 109, 210, 243, 151, 206, 217, 120, 2,
  171, 75, 180, 31, 4, 91, 78, 206, 217, 241, 119, 55, 230, 216, 23, 237, 101,
  21, 89, 132, 84, 100, 3, 255, 90, 197, 237, 139, 209,
]

const secp384r1CompressedFixture = [
  3, 207, 62, 215, 143, 116, 128, 174, 103, 1, 81, 127, 212, 163, 19, 165, 220,
  74, 144, 26, 59, 87, 0, 214, 47, 66, 73, 152, 227, 196, 81, 14, 28, 58, 221,
  178, 63, 150, 119, 62, 195, 99, 63, 60, 42, 223, 207, 28, 65,
]

describe('ecc', () => {
  it('encodeNamedCurves.prime256v1', () => {
    const publicKey = new Uint8Array(prime256v1PublicFixture)
    const compressPoint = encodeNamedCurves.prime256v1(publicKey)
    expect(compressPoint).to.deep.equal(
      new Uint8Array(prime256v1CompressedFixture)
    )
  })

  it('Precondition: publicKey must be the right length.', () => {
    const publicKey = new Uint8Array(5)
    expect(() => encodeNamedCurves.prime256v1(publicKey)).to.throw()
  })

  it('decodeNamedCurves.prime256v1', () => {
    const compressPoint = new Uint8Array(prime256v1CompressedFixture)
    const publicKey = decodeNamedCurves.prime256v1(compressPoint)
    expect(publicKey).to.deep.equal(new Uint8Array(prime256v1PublicFixture))
  })

  it('Precondition: compressedPoint must be the correct length.', () => {
    const compressPoint = new Uint8Array(5)
    expect(() => decodeNamedCurves.prime256v1(compressPoint)).to.throw()
  })

  it('encodeNamedCurves.secp384r1', () => {
    const publicKey = new Uint8Array(secp384r1PublicFixture)
    const compressPoint = encodeNamedCurves.secp384r1(publicKey)
    expect(compressPoint).to.deep.equal(
      new Uint8Array(secp384r1CompressedFixture)
    )
  })

  it('decodeNamedCurves.secp384r1', () => {
    const compressPoint = new Uint8Array(secp384r1CompressedFixture)
    const publicKey = decodeNamedCurves.secp384r1(compressPoint)
    expect(publicKey).to.deep.equal(new Uint8Array(secp384r1PublicFixture))
  })
})
