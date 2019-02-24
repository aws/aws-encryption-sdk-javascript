import { expect } from 'chai'
import 'mocha'
import {readElements} from '../src/read_element'
import {concatBuffers} from '../src/concat_buffers'
import {Buffer} from 'buffer'

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

  it('should return false the buffer does not contain enough expected data', () => {
    const utf8DataStrings = [
      'some utf8 information', '\u00bd + \u00bc = \u00be', 'to encode'
    ]
    const buffData = utf8DataStrings.map(str => new Uint8Array([...Buffer.from(str)]))
    const buff = concatBuffers(...buffData.map(bufStr => {
      const len = Buffer.alloc(2)
      len.writeUInt16BE(bufStr.byteLength, 0)
      return concatBuffers(len, bufStr)
    }))

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
})
