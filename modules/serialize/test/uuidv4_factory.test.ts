// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// tests contains MPL tests: https://github.com/aws/aws-cryptographic-material-providers-library/blob/da6812fa30315fda75d4277f814d1d0e36e22498/StandardLibrary/test/UUID.dfy

import { v3, v5, v1, v4 } from 'uuid'
import { uuidv4Factory } from '../src/uuidv4_factory'
import { expect } from 'chai'

const stringToHexBytes = (input: string): Uint8Array =>
  new Uint8Array(Buffer.from(input, 'hex'))

const hexBytesToString = (input: Uint8Array): string =>
  Buffer.from(input).toString('hex')

const { uuidv4ToCompressedBytes, decompressBytesToUuidv4 } = uuidv4Factory(
  stringToHexBytes,
  hexBytesToString
)

const uuidString = '92382658-b7a0-4d97-9c49-cee4e672a3b3'
const byteUuid = new Uint8Array([
  146, 56, 38, 88, 183, 160, 77, 151, 156, 73, 206, 228, 230, 114, 163, 179,
])
const wrongByteUuid = new Uint8Array([
  146, 56, 38, 88, 183, 160, 77, 151, 156, 73, 206, 228, 230, 114, 163, 178,
])

describe('uuidv4Factory', () => {
  it('Test roundtrip string conversion', () => {
    const stringToBytes = uuidv4ToCompressedBytes(uuidString)
    expect(stringToBytes).has.lengthOf(16)
    const bytesToString = decompressBytesToUuidv4(stringToBytes)
    expect(bytesToString).to.equal(uuidString)
  })

  it('Test roundtrip byte conversion', () => {
    const bytesToString = decompressBytesToUuidv4(byteUuid)
    const stringToBytes = uuidv4ToCompressedBytes(bytesToString)
    expect(stringToBytes).has.lengthOf(16)
    expect(stringToBytes).to.deep.equal(byteUuid)
  })

  it('Test generate and conversion', () => {
    const uuid = v4()
    const uuidBytes = uuidv4ToCompressedBytes(uuid)
    const bytesToString = decompressBytesToUuidv4(uuidBytes)
    const stringToBytes = uuidv4ToCompressedBytes(bytesToString)

    expect(stringToBytes).has.lengthOf(16)
    expect(stringToBytes).to.deep.equal(uuidBytes)

    const uuidStringToBytes = uuidv4ToCompressedBytes(uuid)
    expect(uuidStringToBytes).has.lengthOf(16)
    const uuidBytesToString = decompressBytesToUuidv4(uuidStringToBytes)
    expect(uuidBytesToString).to.equal(uuid)
  })

  describe('decompressBytesToUuidv4', () => {
    it('Precondition: Compressed bytes must have correct byte length', () => {
      expect(() => decompressBytesToUuidv4(new Uint8Array([0]))).to.throw(
        'Compressed uuid has incorrect byte length'
      )
    })

    it('Postcondition: Output string must be valid uuidv4', () => {
      expect(() =>
        decompressBytesToUuidv4(new Uint8Array(Buffer.alloc(16)))
      ).to.throw('Input must represent a uuidv4')
    })

    it('Test success', () => {
      const fromBytes = decompressBytesToUuidv4(byteUuid)
      expect(fromBytes).to.equal(uuidString)
    })

    it('Test failure', () => {
      const fromBytes = decompressBytesToUuidv4(wrongByteUuid)
      expect(fromBytes).to.not.equals(uuidString)
    })
  })

  describe('uuidv4ToCompressedBytes', () => {
    it('Precondition: Input string must be valid uuidv4', () => {
      expect(() => uuidv4ToCompressedBytes(v1())).to.throw(
        'Input must be valid uuidv4'
      )

      const name = 'example.com'
      const namespace = uuidString
      expect(() => uuidv4ToCompressedBytes(v3(name, namespace))).to.throw(
        'Input must be valid uuidv4'
      )

      expect(() => uuidv4ToCompressedBytes(v5(name, namespace))).to.throw(
        'Input must be valid uuidv4'
      )
    })

    it('Postcondition: Compressed bytes must have correct byte length', () => {
      expect(() => uuidv4ToCompressedBytes(uuidString)).to.not.throw()
    })

    it('Test success', () => {
      const fromBytes = uuidv4ToCompressedBytes(uuidString)
      expect(fromBytes).to.deep.equal(byteUuid)
    })

    it('Test failure', () => {
      const fromBytes = uuidv4ToCompressedBytes(uuidString)
      expect(fromBytes).to.not.deep.equals(wrongByteUuid)
    })
  })
})
