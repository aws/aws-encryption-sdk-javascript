// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { readElements } from '../src/read_element'
import { concatBuffers } from '../src/concat_buffers'
import { Buffer } from 'buffer'
import * as fixtures from './fixtures'

function randomNat(limit: number): number {
  return Math.floor(Math.random() * limit)
}

describe('readElements', () => {
  it('should be able to handle multiple elements containing multiple fields without padding', () => {
    const utf8DataStrings = [
      'here',
      'is',
      'some',
      'utf8',
      'information',
      '\u00bd + \u00bc = \u00be',
    ]
    const buffData = utf8DataStrings.map(
      (str) => new Uint8Array([...Buffer.from(str)])
    )
    const buff = concatBuffers(
      ...buffData.map((bufStr) => {
        const len = Buffer.alloc(2)
        len.writeUInt16BE(bufStr.byteLength, 0)
        return concatBuffers(len, bufStr)
      })
    )

    /* The elements in the buffer can be arranged in several ways.
     * For example, we can think of them as six elements with one
     * field each, or as three elements with two fields each.
     */
    const dimensions = [
      [1, 6],
      [2, 3],
      [3, 2],
      [6, 1],
    ]

    dimensions.map(([elementCount, fieldsPerElement]) => {
      const info = readElements(elementCount, fieldsPerElement, buff)

      if (info === false) throw new Error('Fail')
      const elements = info.elements
      expect(elements).to.be.instanceof(Array)
      expect(elements.length).to.eql(elementCount)

      for (let eCount = 0; eCount < elementCount; eCount++) {
        const element = info.elements[eCount]
        expect(element).to.be.instanceof(Array)
        expect(element.length).to.eql(fieldsPerElement)
        for (let fCount = 0; fCount < fieldsPerElement; fCount++) {
          const field = element[fCount]
          expect(field).to.deep.equal(
            buffData[eCount * fieldsPerElement + fCount]
          )
          expect(Buffer.from(field).toString()).to.deep.equal(
            utf8DataStrings[eCount * fieldsPerElement + fCount]
          )
        }
      }

      expect(info.readPos).to.eql(buff.byteLength)
    })
  })

  it('should be able to handle multiple elements containing multiple fields with various padding', () => {
    let numberOfRuns = 16
    const maxPaddingLength = 1024
    const utf8DataStrings = [
      'here',
      'is',
      'some',
      'utf8',
      'information',
      '\u00bd + \u00bc = \u00be',
    ]
    const buffData = utf8DataStrings.map(
      (str) => new Uint8Array([...Buffer.from(str)])
    )
    const mainBuffer = concatBuffers(
      ...buffData.map((bufStr) => {
        const len = Buffer.alloc(2)
        len.writeUInt16BE(bufStr.byteLength, 0)
        return concatBuffers(len, bufStr)
      })
    )

    const dimensions = [
      [1, 6],
      [2, 3],
      [3, 2],
      [6, 1],
    ]

    while (numberOfRuns--) {
      const leftPadding = Buffer.alloc(randomNat(maxPaddingLength))
      const rightPadding = Buffer.alloc(randomNat(maxPaddingLength))
      const buff = concatBuffers(leftPadding, mainBuffer, rightPadding)

      dimensions.map(([elementCount, fieldsPerElement]) => {
        const info = readElements(
          elementCount,
          fieldsPerElement,
          buff,
          leftPadding.byteLength
        )

        if (info === false) throw new Error('Fail')
        const elements = info.elements
        expect(elements).to.be.instanceof(Array)
        expect(elements.length).to.eql(elementCount)

        for (let eCount = 0; eCount < elementCount; eCount++) {
          const element = info.elements[eCount]
          expect(element).to.be.instanceof(Array)
          expect(element.length).to.eql(fieldsPerElement)
          for (let fCount = 0; fCount < fieldsPerElement; fCount++) {
            const field = element[fCount]
            expect(field).to.deep.equal(
              buffData[eCount * fieldsPerElement + fCount]
            )
            expect(Buffer.from(field).toString()).to.deep.equal(
              utf8DataStrings[eCount * fieldsPerElement + fCount]
            )
          }
        }

        expect(info.readPos).to.eql(
          leftPadding.byteLength + mainBuffer.byteLength
        )
      })
    }
  })

  it('Precondition: readPos must be non-negative and within the byte length of the buffer given.', () => {
    const buff = new Uint8Array(32)
    const readPosBeyondBuff = buff.byteLength + 1
    expect(() => readElements(1, 1, buff, readPosBeyondBuff)).to.throw()
  })

  it('Precondition: elementCount and fieldsPerElement must be non-negative.', () => {
    const buff = new Uint8Array(32)
    expect(() => readElements(-1, 1, buff)).to.throw()
    expect(() => readElements(1, -1, buff)).to.throw()
    expect(() => readElements(-1, -1, buff)).to.throw()
  })

  it('Check for early return (Postcondition): Enough data must exist to read the Uint16 length value.; Check for early return (Postcondition): Enough data must exist length of the value.', () => {
    const utf8DataStrings = [
      'here',
      'is',
      'some',
      'utf8',
      'information',
      '\u00bd + \u00bc = \u00be',
    ]
    const buffData = utf8DataStrings.map(
      (str) => new Uint8Array([...Buffer.from(str)])
    )
    const buff = concatBuffers(
      ...buffData.map((bufStr) => {
        const len = Buffer.alloc(2)
        len.writeUInt16BE(bufStr.byteLength, 0)
        return concatBuffers(len, bufStr)
      })
    )

    /* Will return false when trying to read the length of the seventh element */
    const infoFalse1 = readElements(1, 7, buff)
    expect(infoFalse1).to.equal(false)

    /* Will return false when trying to read the sixth element */
    const infoFalse2 = readElements(1, 6, buff.slice(0, buff.byteLength - 1))
    expect(infoFalse2).to.equal(false)
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    /* The EncryptionContext section starts with a length and count before
     * getting to the `elements` section that readElements is built to handle.
     * This means reading from the beginning should fail and moving the
     * read position past the length and count should succeed.
     */
    const buff = fixtures.basicEncryptionContext()
    expect(readElements(4, 1, buff, 0)).to.equal(false)
    expect(readElements(4, 1, buff, 4)).to.not.equal(false)
    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(
      buff.buffer,
      4,
      buff.byteLength - 4
    )
    expect(readElements(4, 1, sharingArrayBuffer)).to.not.equal(false)
  })
})
