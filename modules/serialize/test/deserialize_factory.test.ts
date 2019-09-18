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
import { deserializeFactory } from '../src/deserialize_factory'
import { concatBuffers } from '../src'
import { WebCryptoAlgorithmSuite, EncryptedDataKey } from '@aws-crypto/material-management'
import * as fixtures from './fixtures'
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString()
describe('deserializeFactory:decodeEncryptionContext', () => {
  it('returns context object', () => {
    const { decodeEncryptionContext } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)

    const contextSection = fixtures.basicEncryptionContext()

    const test = decodeEncryptionContext(contextSection.slice(2))
    expect(test).to.have.property('some')
      .and.to.eql('public')
    expect(test).to.have.property('information')
      .and.to.eql('\u00bd + \u00bc = \u00be')
  })

  it('Check for early return (Postcondition): The case of 0 length is defined as an empty object.', () => {
    const { decodeEncryptionContext } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const test = decodeEncryptionContext(new Uint8Array(0))
    expect(test).to.be.deep.equal({})
  })

  it('Postcondition: Since the encryption context has a length, it must have pairs.', () => {
    const { decodeEncryptionContext } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)

    const badContextSection = fixtures.missingDataEncryptionContext().slice(2)
    expect(() => decodeEncryptionContext(badContextSection)).to.throw()
  })

  it('Postcondition: The byte length of the encodedEncryptionContext must match the readPos.', () => {
    const { decodeEncryptionContext } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)

    const badContextSection = fixtures.tooMuchDataEncryptionContext().slice(2)
    expect(() => decodeEncryptionContext(badContextSection)).to.throw()
  })

  it('Postcondition: The number of keys in the encryptionContext must match the pairsCount.', () => {
    const { decodeEncryptionContext } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)

    const badContextSection = fixtures.duplicateKeysEncryptionContext().slice(2)
    expect(() => decodeEncryptionContext(badContextSection)).to.throw()
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    const { decodeEncryptionContext } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)

    /* Create a Uint8Array that has an a valid FrameHeader but is proceeded by "invalid" bytes. (the Length part) */
    const buff = fixtures.basicEncryptionContext()
    expect(() => decodeEncryptionContext(buff)).to.throw()
    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(buff.buffer, 2, buff.byteLength - 2)
    const test = decodeEncryptionContext(sharingArrayBuffer)
    expect(test).to.have.property('some')
      .and.to.eql('public')
    expect(test).to.have.property('information')
      .and.to.eql('\u00bd + \u00bc = \u00be')
  })
})

describe('deserializeFactory:deserializeEncryptedDataKeys', () => {
  it('return EncryptedDataKey info', () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const buffer = fixtures.encryptedDataKey()
    const test = deserializeEncryptedDataKeys(buffer, 0)
    if (!test) throw new Error('fail')
    expect(test).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)
    expect(test).to.have.property('readPos')
      .and.to.eql(buffer.byteLength)

    const { encryptedDataKeys } = test

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].rawInfo).to.deep.equal(new Uint8Array([ 102, 105, 114, 115, 116, 75, 101, 121 ]))
    expect(encryptedDataKeys[0].encryptedDataKey)
      .to.deep.equal(new Uint8Array([1, 2, 3, 4, 5]))

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].rawInfo).to.deep.equal(new Uint8Array([ 115, 101, 99, 111, 110, 100, 75, 101, 121 ]))
    expect(encryptedDataKeys[1].encryptedDataKey)
      .to.deep.equal(new Uint8Array([6, 7, 8, 9, 0]))
  })

  it(`Check for early return (Postcondition): Need to have at least Uint16 (2) bytes of data.
      Check for early return (Postcondition): readElement will return false if there is not enough data.`, () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const buffer = fixtures.encryptedDataKey()

    // By testing every buffer size, we check every boundary condition for "not enough data"
    for (let i = 0; buffer.byteLength > i; i++) {
      const test = deserializeEncryptedDataKeys(buffer.slice(0, i), 0)
      expect(test).to.eql(false)
    }
  })

  it('Precondition: There must be at least 1 EncryptedDataKey element.', () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const buffer = new Uint8Array(2)

    expect(() => deserializeEncryptedDataKeys(buffer, 0)).to.throw()
  })

  it('Precondition: startPos must be within the byte length of the buffer given.', () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const buffer = new Uint8Array(10)

    expect(() => deserializeEncryptedDataKeys(buffer, buffer.byteLength + 1)).to.throw()
    expect(() => deserializeEncryptedDataKeys(buffer, -1)).to.throw()
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    /* Create a Uint8Array that has an a valid FrameHeader but is proceeded by "invalid" bytes. */
    const { deserializeEncryptedDataKeys } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const buffer = concatBuffers(new Uint8Array(5), fixtures.encryptedDataKey())
    expect(() => deserializeEncryptedDataKeys(buffer, 0)).to.throw()
    // Now we verify that the if we read from after the "invalid" section everything is OK.
    const verify = deserializeEncryptedDataKeys(buffer, 5)
    expect(verify).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)
    expect(verify).to.have.property('readPos')
      .and.to.eql(buffer.byteLength)

    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(buffer.buffer, 5, buffer.byteLength - 5)
    const test = deserializeEncryptedDataKeys(sharingArrayBuffer, 0)
    if (!test) throw new Error('fail')
    expect(test).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)
    expect(test).to.have.property('readPos')
      .and.to.eql(sharingArrayBuffer.byteLength)

    const { encryptedDataKeys } = test

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey)
      .to.deep.equal(new Uint8Array([1, 2, 3, 4, 5]))

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey)
      .to.deep.equal(new Uint8Array([6, 7, 8, 9, 0]))
  })
})

describe('deserializeFactory:deserializeMessageHeader', () => {
  it('return header information with context', () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
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

    const { messageHeader } = test
    expect(messageHeader).to.have.property('version')
      .and.to.eql(1)
    expect(messageHeader).to.have.property('type')
      .and.to.eql(128)
    expect(messageHeader).to.have.property('suiteId')
      .and.to.eql(0x0014)
    expect(messageHeader).to.have.property('messageId')
      .and.to.deep.equal(new Uint8Array(16).fill(3))
    expect(messageHeader).to.have.property('encryptionContext')
      .and.to.deep.equal({ some: 'public', information: '½ + ¼ = ¾' })

    expect(messageHeader).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)

    const { encryptedDataKeys } = messageHeader

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey)
      .to.deep.equal(new Uint8Array([1, 2, 3, 4, 5]))

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey)
      .to.deep.equal(new Uint8Array([6, 7, 8, 9, 0]))

    expect(messageHeader).to.have.property('contentType')
      .and.to.eql(2)
    expect(messageHeader).to.have.property('headerIvLength')
      .and.to.eql(12)
    expect(messageHeader).to.have.property('frameLength')
      .and.to.eql(4096)
  })

  it(`Check for early return (Postcondition): Not Enough Data. Need to have at least 22 bytes of data to begin parsing.
      Check for early return (Postcondition): Not Enough Data. Need to have all of the context in bytes before we can parse the next section.
      Check for early return (Postcondition): Not Enough Data. deserializeEncryptedDataKeys will return false if it does not have enough data.
      Check for early return (Postcondition): Not Enough Data. Need to have the remaining fixed length data to parse. `, () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const basicMessageHeader = fixtures.basicMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      basicMessageHeader,
      headerIv,
      headerAuthTag
    )

    // By testing every buffer size, we check every boundary condition for "not enough data"
    for (let i = 0; buffer.byteLength > i; i++) {
      const test = deserializeMessageHeader(buffer.slice(0, i))
      expect(test).to.eql(false)
    }
  })

  it('return header information without context', () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
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

    const { messageHeader } = test
    expect(messageHeader).to.have.property('version')
      .and.to.eql(1)
    expect(messageHeader).to.have.property('type')
      .and.to.eql(128)
    expect(messageHeader).to.have.property('suiteId')
      .and.to.eql(0x0014)
    expect(messageHeader).to.have.property('messageId')
      .and.to.deep.equal(new Uint8Array(16).fill(3))
    expect(messageHeader).to.have.property('encryptionContext')
      .and.to.deep.equal({})

    expect(messageHeader).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)

    const { encryptedDataKeys } = messageHeader

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey)
      .to.deep.equal(new Uint8Array([1, 2, 3, 4, 5]))

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey)
      .to.deep.equal(new Uint8Array([6, 7, 8, 9, 0]))

    expect(messageHeader).to.have.property('contentType')
      .and.to.eql(2)
    expect(messageHeader).to.have.property('headerIvLength')
      .and.to.eql(12)
    expect(messageHeader).to.have.property('frameLength')
      .and.to.eql(4096)
  })

  it('Header without context should stream correctly i.e not return data when not enough is given.', () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
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

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const basicMessageHeader = fixtures.basicMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    /* Create a Uint8Array that has an a valid FrameHeader but is proceeded by "invalid" bytes. */
    const buffer = concatBuffers(
      new Uint8Array(5),
      basicMessageHeader,
      headerIv,
      headerAuthTag
    )

    expect(() => deserializeMessageHeader(buffer)).to.throw()

    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(buffer.buffer, 5, buffer.byteLength - 5)
    const test = deserializeMessageHeader(sharingArrayBuffer)

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

    const { messageHeader } = test
    expect(messageHeader).to.have.property('version')
      .and.to.eql(1)
    expect(messageHeader).to.have.property('type')
      .and.to.eql(128)
    expect(messageHeader).to.have.property('suiteId')
      .and.to.eql(0x0014)
    expect(messageHeader).to.have.property('messageId')
      .and.to.deep.equal(new Uint8Array(16).fill(3))
    expect(messageHeader).to.have.property('encryptionContext')
      .and.to.deep.equal({ some: 'public', information: '½ + ¼ = ¾' })

    expect(messageHeader).to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)

    const { encryptedDataKeys } = messageHeader

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey)
      .to.deep.equal(new Uint8Array([1, 2, 3, 4, 5]))

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey)
      .to.deep.equal(new Uint8Array([6, 7, 8, 9, 0]))

    expect(messageHeader).to.have.property('contentType')
      .and.to.eql(2)
    expect(messageHeader).to.have.property('headerIvLength')
      .and.to.eql(12)
    expect(messageHeader).to.have.property('frameLength')
      .and.to.eql(4096)
  })

  it('Precondition: version and type must be the required values.', () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    expect(() => deserializeMessageHeader(fixtures.versionNotValidMessageHeader())).to.throw('Malformed Header')
    expect(() => deserializeMessageHeader(fixtures.typeNotValidMessageHeader())).to.throw('Malformed Header')
  })

  it('Precondition: suiteId must match supported algorithm suite', () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const suiteIdNotValidMessageHeader = fixtures.suiteIdNotValidMessageHeader()
    expect(() => deserializeMessageHeader(suiteIdNotValidMessageHeader)).to.throw('Unsupported algorithm suite.')
  })

  it('Postcondition: reservedBytes are defined as 0,0,0,0', () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const reservedBytesNoZeroMessageHeader = fixtures.reservedBytesNoZeroMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      reservedBytesNoZeroMessageHeader,
      headerIv,
      headerAuthTag
    )
    expect(() => deserializeMessageHeader(buffer)).to.throw('Malformed Header')
  })

  it('Postcondition: The headerIvLength must match the algorithm suite specification.', () => {
    const { deserializeMessageHeader } = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
    const reservedBytesNoZeroMessageHeader = fixtures.ivLengthMismatchMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      reservedBytesNoZeroMessageHeader,
      headerIv,
      headerAuthTag
    )
    expect(() => deserializeMessageHeader(buffer)).to.throw('Malformed Header')
  })
})
