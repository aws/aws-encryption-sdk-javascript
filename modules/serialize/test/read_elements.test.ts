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
import { readElements } from '../src/read_element'
import { concatBuffers } from '../src/concat_buffers'
import { Buffer } from 'buffer'
import * as fixtures from './fixtures'

describe('readElements', () => {
  it('should be able to find one element', () => {
    const len = Buffer.alloc(2)
    len.writeUInt16BE(4, 0)
    const data = new Uint8Array([...Buffer.from('data')])
    const buff = concatBuffers(len, data)
    const info = readElements(1, buff, 0)
    if (info === false) throw new Error('Fail')
    expect(info.elements).to.be.instanceof(Array)
    expect(info.elements.length).to.eql(1)
    expect(info.elements[0]).to.deep.equal(data)
    expect(info.readPos).to.eql(6)
  })

  it('should be able to handle multiple elements', () => {
    const utf8DataStrings = [
      'some utf8 information', '\u00bd + \u00bc = \u00be', 'to encode'
    ]
    const buffData = utf8DataStrings.map(str => new Uint8Array([...Buffer.from(str)]))
    const buff = concatBuffers(...buffData.map(bufStr => {
      const len = Buffer.alloc(2)
      len.writeUInt16BE(bufStr.byteLength, 0)
      return concatBuffers(len, bufStr)
    }))

    const info = readElements(3, buff, 0)

    if (info === false) throw new Error('Fail')
    expect(info.elements).to.be.instanceof(Array)
    expect(info.elements.length).to.eql(3)
    expect(info.elements[0]).to.deep.equal(buffData[0])
    expect(info.elements[1]).to.deep.equal(buffData[1])
    expect(info.elements[2]).to.deep.equal(buffData[2])
    expect(Buffer.from(info.elements[0]).toString()).to.deep.equal(utf8DataStrings[0])
    expect(Buffer.from(info.elements[1]).toString()).to.deep.equal(utf8DataStrings[1])
    expect(Buffer.from(info.elements[2]).toString()).to.deep.equal(utf8DataStrings[2])
    expect(info.readPos).to.eql(48)
  })

  it('should be able to handle multiple elements when not reading from the beginning', () => {
    const utf8DataStrings = [
      'some utf8 information', '\u00bd + \u00bc = \u00be', 'to encode'
    ]
    const buffData = utf8DataStrings.map(str => new Uint8Array([...Buffer.from(str)]))
    const padding = Buffer.alloc(10)
    const buff = concatBuffers(padding, ...buffData.map(bufStr => {
      const len = Buffer.alloc(2)
      len.writeUInt16BE(bufStr.byteLength, 0)
      return concatBuffers(len, bufStr)
    }))

    const info = readElements(3, buff, padding.length)

    if (info === false) throw new Error('Fail')
    expect(info.elements).to.be.instanceof(Array)
    expect(info.elements.length).to.eql(3)
    expect(info.elements[0]).to.deep.equal(buffData[0])
    expect(info.elements[1]).to.deep.equal(buffData[1])
    expect(info.elements[2]).to.deep.equal(buffData[2])
    expect(Buffer.from(info.elements[0]).toString()).to.deep.equal(utf8DataStrings[0])
    expect(Buffer.from(info.elements[1]).toString()).to.deep.equal(utf8DataStrings[1])
    expect(Buffer.from(info.elements[2]).toString()).to.deep.equal(utf8DataStrings[2])
    expect(info.readPos).to.eql(58)
  })

  it('should be able to handle multiple elements with padding on both sides', () => {
    const utf8DataStrings = [
      'some utf8 information', '\u00bd + \u00bc = \u00be', 'to encode'
    ]
    const buffData = utf8DataStrings.map(str => new Uint8Array([...Buffer.from(str)]))
    const padding = Buffer.alloc(10)
    const buff = concatBuffers(padding, ...buffData.map(bufStr => {
      const len = Buffer.alloc(2)
      len.writeUInt16BE(bufStr.byteLength, 0)
      return concatBuffers(len, bufStr)
    }), padding)

    const info = readElements(3, buff, padding.length)

    if (info === false) throw new Error('Fail')
    expect(info.elements).to.be.instanceof(Array)
    expect(info.elements.length).to.eql(3)
    expect(info.elements[0]).to.deep.equal(buffData[0])
    expect(info.elements[1]).to.deep.equal(buffData[1])
    expect(info.elements[2]).to.deep.equal(buffData[2])
    expect(Buffer.from(info.elements[0]).toString()).to.deep.equal(utf8DataStrings[0])
    expect(Buffer.from(info.elements[1]).toString()).to.deep.equal(utf8DataStrings[1])
    expect(Buffer.from(info.elements[2]).toString()).to.deep.equal(utf8DataStrings[2])
    expect(info.readPos).to.eql(58)
  })

  it('Precondition: Enough data must exist to read the Uin16 length value.; Precondition: Enough data must exist length of the value.', () => {
    const utf8DataStrings = [
      'some utf8 information', '\u00bd + \u00bc = \u00be', 'to encode'
    ]
    const buffData = utf8DataStrings.map(str => new Uint8Array([...Buffer.from(str)]))
    const buff = concatBuffers(...buffData.map(bufStr => {
      const len = Buffer.alloc(2)
      len.writeUInt16BE(bufStr.byteLength, 0)
      return concatBuffers(len, bufStr)
    }))

    // By testing every combination of byte length possible
    // Both loop invariants are covered.
    for (let i = 0; buff.byteLength > i; i++) {
      const info = readElements(3, buff.slice(0, i), 0)
      expect(info).to.eql(false)
    }
    // Engage pedantry...
    const info = readElements(3, buff.slice(0, buff.byteLength), 0)
    if (info === false) throw new Error('Fail')
    expect(info.elements).to.be.instanceof(Array)
    expect(info.elements.length).to.eql(3)
    expect(info.elements[0]).to.deep.equal(buffData[0])
    expect(info.elements[1]).to.deep.equal(buffData[1])
    expect(info.elements[2]).to.deep.equal(buffData[2])
    expect(Buffer.from(info.elements[0]).toString()).to.deep.equal(utf8DataStrings[0])
    expect(Buffer.from(info.elements[1]).toString()).to.deep.equal(utf8DataStrings[1])
    expect(Buffer.from(info.elements[2]).toString()).to.deep.equal(utf8DataStrings[2])
    expect(info.readPos).to.eql(48)
  })

  it('Precondition: readPos must be within the byte length of the buffer given.', () => {
    const buff = new Uint8Array(32)
    const readPosBeyondBuff = buff.byteLength + 1
    expect(() => readElements(1, buff, readPosBeyondBuff)).to.throw()
  })

  it('Precondition: There must be at least 1 element to find.', () => {
    const buff = new Uint8Array(32)
    expect(() => readElements(-1, buff)).to.throw()
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    /* The EncryptionContext section starts with a length and count before
     * getting to the `elements` section that readElements is built to handle.
     * This means reading from the beginning should fail and moving the
     * read position past the length and count should succeed.
     */
    const buff = fixtures.basicEncryptionContext()
    expect(readElements(4, buff, 0)).to.equal(false)
    expect(readElements(4, buff, 4)).to.not.equal(false)
    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(buff.buffer, 4, buff.byteLength - 4)
    expect(readElements(4, sharingArrayBuffer)).to.not.equal(false)
  })
})
