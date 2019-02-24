import { expect } from 'chai'
import 'mocha'
import {deserializeFactory} from '../src/deserialize_factory'
import {concatBuffers} from '../src'
import {WebCryptoAlgorithmSuite, EncryptedDataKey} from '@aws-crypto/material-management'
import * as fixtures from './fixtures'
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString()
describe('deserializeFactory:decodeEncryptionContext', () => {
  it('returns context object', () => {
    const {decodeEncryptionContext} = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)

    const contextSection = fixtures.basicEncryptionContext()
    
    const test = decodeEncryptionContext(contextSection.slice(2))
    expect(test).to.have.property('some')
      .and.to.eql('public')
    expect(test).to.have.property('information')
      .and.to.eql('\u00bd + \u00bc = \u00be')
  })

  it('return and empty object', () => {
    const {decodeEncryptionContext} = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const test = decodeEncryptionContext(new Uint8Array(0))
    expect(test).to.be.deep.equal({})
  })
})

describe('deserializeFactory:deserializeEncryptedDataKeys', () => {
  it('return EncryptedDataKey info', () => {
    const {deserializeEncryptedDataKeys} = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const buffer = fixtures.encryptedDataKey()
    const test = deserializeEncryptedDataKeys(buffer, 0)
    if (!test) throw new Error('fail')
    expect(test).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)
    expect(test).to.have.property('readPos')
      .and.to.eql(buffer.byteLength)

    const {encryptedDataKeys} = test

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey)
      .to.deep.equal(new Uint8Array([1,2,3,4,5]))

      expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey)
      .to.deep.equal(new Uint8Array([6,7,8,9,0]))
  })

  it('return false', () => {
    const {deserializeEncryptedDataKeys} = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const buffer = fixtures.encryptedDataKey()

    for (let i = 0; buffer.byteLength > i; i++) {
      const test = deserializeEncryptedDataKeys(buffer.slice(0, i), 0)
      expect(test).to.eql(false)
    }
  })
})

describe('deserializeFactory:deserializeMessageHeader', () => {
  it('return header information with context', () => {
    const {deserializeMessageHeader} = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const basicMessageHeader = fixtures.basicMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      basicMessageHeader,
      headerIv,
      headerAuthTag
    )

    const test = deserializeMessageHeader(buffer)
    if (!test) throw new Error('fail')
    expect(test).to.have.property('headerLength')
      .and.to.deep.equal(basicMessageHeader.byteLength)
    expect(test).to.have.property('rawHeader')
      .and.to.deep.equal(basicMessageHeader)
    expect(test).to.have.property('headerIv')
      .and.to.deep.equal(headerIv)
    expect(test).to.have.property('headerAuthTag')
      .and.to.deep.equal(headerAuthTag)

    expect(test).to.have.property('algorithmSuite')
      .and.to.be.instanceOf(WebCryptoAlgorithmSuite)
    expect(test.algorithmSuite.id).to.eql(0x0014)

    const {messageHeader} = test
    expect(messageHeader).to.have.property('version')
      .and.to.eql(1)
    expect(messageHeader).to.have.property('type')
      .and.to.eql(128)
    expect(messageHeader).to.have.property('algorithmId')
      .and.to.eql(0x0014)
    expect(messageHeader).to.have.property('messageId')
      .and.to.deep.equal(new Uint8Array(16).fill(3))
    expect(messageHeader).to.have.property('encryptionContext')
      .and.to.deep.equal({ some: 'public', information: '½ + ¼ = ¾' })

    expect(messageHeader).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)

    const {encryptedDataKeys} = messageHeader

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey)
      .to.deep.equal(new Uint8Array([1,2,3,4,5]))

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey)
      .to.deep.equal(new Uint8Array([6,7,8,9,0]))

    expect(messageHeader).to.have.property('contentType')
      .and.to.eql(2)
    expect(messageHeader).to.have.property('headerIvLength')
      .and.to.eql(12)
    expect(messageHeader).to.have.property('frameLength')
      .and.to.eql(4096)
  })

  it('return false from partial header with context', () => {
    const {deserializeMessageHeader} = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const basicMessageHeader = fixtures.basicMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      basicMessageHeader,
      headerIv,
      headerAuthTag
    )

    for (let i = 0; buffer.byteLength > i; i++) {
      const test = deserializeMessageHeader(buffer.slice(0, i))
      expect(test).to.eql(false)
    }
  })

  it('return header information without context', () => {
    const {deserializeMessageHeader} = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const zeroByteEncryptionContextMessageHeader = fixtures.zeroByteEncryptionContextMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      zeroByteEncryptionContextMessageHeader,
      headerIv,
      headerAuthTag
    )

    const test = deserializeMessageHeader(buffer)
    if (!test) throw new Error('fail')
    expect(test).to.have.property('headerLength')
      .and.to.deep.equal(zeroByteEncryptionContextMessageHeader.byteLength)
    expect(test).to.have.property('rawHeader')
      .and.to.deep.equal(zeroByteEncryptionContextMessageHeader)
    expect(test).to.have.property('headerIv')
      .and.to.deep.equal(headerIv)
    expect(test).to.have.property('headerAuthTag')
      .and.to.deep.equal(headerAuthTag)

    expect(test).to.have.property('algorithmSuite')
      .and.to.be.instanceOf(WebCryptoAlgorithmSuite)
    expect(test.algorithmSuite.id).to.eql(0x0014)

    const {messageHeader} = test
    expect(messageHeader).to.have.property('version')
      .and.to.eql(1)
    expect(messageHeader).to.have.property('type')
      .and.to.eql(128)
    expect(messageHeader).to.have.property('algorithmId')
      .and.to.eql(0x0014)
    expect(messageHeader).to.have.property('messageId')
      .and.to.deep.equal(new Uint8Array(16).fill(3))
    expect(messageHeader).to.have.property('encryptionContext')
      .and.to.deep.equal({})

    expect(messageHeader).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)

    const {encryptedDataKeys} = messageHeader

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey)
      .to.deep.equal(new Uint8Array([1,2,3,4,5]))

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey)
      .to.deep.equal(new Uint8Array([6,7,8,9,0]))

    expect(messageHeader).to.have.property('contentType')
      .and.to.eql(2)
    expect(messageHeader).to.have.property('headerIvLength')
      .and.to.eql(12)
    expect(messageHeader).to.have.property('frameLength')
      .and.to.eql(4096)
  })

  it('return false from partial header without context', () => {
    const {deserializeMessageHeader} = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const zeroByteEncryptionContextMessageHeader = fixtures.zeroByteEncryptionContextMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      zeroByteEncryptionContextMessageHeader,
      headerIv,
      headerAuthTag
    )

    for (let i = 0; buffer.byteLength > i; i++) {
      const test = deserializeMessageHeader(buffer.slice(0, i))
      expect(test).to.eql(false)
    }
  })
})
