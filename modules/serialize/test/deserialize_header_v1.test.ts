// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { concatBuffers } from '../src'
import { deserializeHeaderV1Factory } from '../src/deserialize_header_v1'
import { decodeEncryptionContextFactory } from '../src/decode_encryption_context'
import { deserializeEncryptedDataKeysFactory } from '../src/deserialize_encrypted_data_keys'
import * as fixtures from './fixtures'
import {
  EncryptedDataKey,
  WebCryptoAlgorithmSuite,
} from '@aws-crypto/material-management'

const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString()

const decodeEncryptionContext = decodeEncryptionContextFactory(toUtf8)
const deserializeEncryptedDataKeys = deserializeEncryptedDataKeysFactory(toUtf8)

describe('deserializeFactory:deserializeMessageHeader', () => {
  it('return header information with context', () => {
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    const basicMessageHeader = fixtures.basicMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(basicMessageHeader, headerIv, headerAuthTag)

    const test = deserializeMessageHeader(buffer)
    if (!test) throw new Error('fail')
    expect(test)
      .to.have.property('headerLength')
      .and.to.deep.equal(basicMessageHeader.byteLength)
    expect(test)
      .to.have.property('rawHeader')
      .and.to.deep.equal(basicMessageHeader)
    expect(test).to.have.property('headerAuth')
    expect(test.headerAuth)
      .to.have.property('headerIv')
      .and.to.deep.equal(headerIv)
    expect(test.headerAuth)
      .to.have.property('headerAuthTag')
      .and.to.deep.equal(headerAuthTag)

    expect(test)
      .to.have.property('algorithmSuite')
      .and.to.be.instanceOf(WebCryptoAlgorithmSuite)
    expect(test.algorithmSuite.id).to.eql(0x0014)

    const { messageHeader } = test
    expect(messageHeader).to.have.property('version').and.to.eql(1)
    expect(messageHeader).to.have.property('type').and.to.eql(128)
    expect(messageHeader).to.have.property('suiteId').and.to.eql(0x0014)
    expect(messageHeader)
      .to.have.property('messageId')
      .and.to.deep.equal(new Uint8Array(16).fill(3))
    expect(messageHeader)
      .to.have.property('encryptionContext')
      .and.to.deep.equal({ some: 'public', information: '½ + ¼ = ¾' })

    expect(messageHeader)
      .to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)

    const { encryptedDataKeys } = messageHeader

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey).to.deep.equal(
      new Uint8Array([1, 2, 3, 4, 5])
    )

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey).to.deep.equal(
      new Uint8Array([6, 7, 8, 9, 0])
    )

    expect(messageHeader).to.have.property('contentType').and.to.eql(2)
    expect(messageHeader).to.have.property('headerIvLength').and.to.eql(12)
    expect(messageHeader).to.have.property('frameLength').and.to.eql(4096)
  })

  it(`Check for early return (Postcondition): Not Enough Data. Need to have at least 22 bytes of data to begin parsing.
      Check for early return (Postcondition): Not Enough Data. Need to have all of the context in bytes before we can parse the next section.
      Check for early return (Postcondition): Not Enough Data. deserializeEncryptedDataKeys will return false if it does not have enough data.
      Check for early return (Postcondition): Not Enough Data. Need to have the remaining fixed length data to parse. `, () => {
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    const basicMessageHeader = fixtures.basicMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(basicMessageHeader, headerIv, headerAuthTag)

    // By testing every buffer size, we check every boundary condition for "not enough data"
    for (let i = 0; buffer.byteLength > i; i++) {
      const test = deserializeMessageHeader(buffer.slice(0, i))
      expect(test).to.eql(false)
    }
  })

  it('return header information without context', () => {
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    const zeroByteEncryptionContextMessageHeader =
      fixtures.zeroByteEncryptionContextMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      zeroByteEncryptionContextMessageHeader,
      headerIv,
      headerAuthTag
    )

    const test = deserializeMessageHeader(buffer)
    if (!test) throw new Error('fail')
    expect(test)
      .to.have.property('headerLength')
      .and.to.deep.equal(zeroByteEncryptionContextMessageHeader.byteLength)
    expect(test)
      .to.have.property('rawHeader')
      .and.to.deep.equal(zeroByteEncryptionContextMessageHeader)
    expect(test).to.have.property('headerAuth')
    expect(test.headerAuth)
      .to.have.property('headerIv')
      .and.to.deep.equal(headerIv)
    expect(test.headerAuth)
      .to.have.property('headerAuthTag')
      .and.to.deep.equal(headerAuthTag)

    expect(test)
      .to.have.property('algorithmSuite')
      .and.to.be.instanceOf(WebCryptoAlgorithmSuite)
    expect(test.algorithmSuite.id).to.eql(0x0014)

    const { messageHeader } = test
    expect(messageHeader).to.have.property('version').and.to.eql(1)
    expect(messageHeader).to.have.property('type').and.to.eql(128)
    expect(messageHeader).to.have.property('suiteId').and.to.eql(0x0014)
    expect(messageHeader)
      .to.have.property('messageId')
      .and.to.deep.equal(new Uint8Array(16).fill(3))
    expect(messageHeader)
      .to.have.property('encryptionContext')
      .and.to.deep.equal({})

    expect(messageHeader)
      .to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)

    const { encryptedDataKeys } = messageHeader

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey).to.deep.equal(
      new Uint8Array([1, 2, 3, 4, 5])
    )

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey).to.deep.equal(
      new Uint8Array([6, 7, 8, 9, 0])
    )

    expect(messageHeader).to.have.property('contentType').and.to.eql(2)
    expect(messageHeader).to.have.property('headerIvLength').and.to.eql(12)
    expect(messageHeader).to.have.property('frameLength').and.to.eql(4096)
  })

  it('Header without context should stream correctly i.e not return data when not enough is given.', () => {
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    const zeroByteEncryptionContextMessageHeader =
      fixtures.zeroByteEncryptionContextMessageHeader()
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
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
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
    const sharingArrayBuffer = new Uint8Array(
      buffer.buffer,
      5,
      buffer.byteLength - 5
    )
    const test = deserializeMessageHeader(sharingArrayBuffer)

    if (!test) throw new Error('fail')
    expect(test)
      .to.have.property('headerLength')
      .and.to.deep.equal(basicMessageHeader.byteLength)
    expect(test)
      .to.have.property('rawHeader')
      .and.to.deep.equal(basicMessageHeader)
    expect(test).to.have.property('headerAuth')
    expect(test.headerAuth)
      .to.have.property('headerIv')
      .and.to.deep.equal(headerIv)
    expect(test.headerAuth)
      .to.have.property('headerAuthTag')
      .and.to.deep.equal(headerAuthTag)

    expect(test)
      .to.have.property('algorithmSuite')
      .and.to.be.instanceOf(WebCryptoAlgorithmSuite)
    expect(test.algorithmSuite.id).to.eql(0x0014)

    const { messageHeader } = test
    expect(messageHeader).to.have.property('version').and.to.eql(1)
    expect(messageHeader).to.have.property('type').and.to.eql(128)
    expect(messageHeader).to.have.property('suiteId').and.to.eql(0x0014)
    expect(messageHeader)
      .to.have.property('messageId')
      .and.to.deep.equal(new Uint8Array(16).fill(3))
    expect(messageHeader)
      .to.have.property('encryptionContext')
      .and.to.deep.equal({ some: 'public', information: '½ + ¼ = ¾' })

    expect(messageHeader)
      .to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)

    const { encryptedDataKeys } = messageHeader

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].encryptedDataKey).to.deep.equal(
      new Uint8Array([1, 2, 3, 4, 5])
    )

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].encryptedDataKey).to.deep.equal(
      new Uint8Array([6, 7, 8, 9, 0])
    )

    expect(messageHeader).to.have.property('contentType').and.to.eql(2)
    expect(messageHeader).to.have.property('headerIvLength').and.to.eql(12)
    expect(messageHeader).to.have.property('frameLength').and.to.eql(4096)
  })

  it('Precondition: version and type must be the required values.', () => {
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    expect(() =>
      deserializeMessageHeader(fixtures.versionNotValidMessageHeader())
    ).to.throw('Malformed Header')
    expect(() =>
      deserializeMessageHeader(fixtures.typeNotValidMessageHeader())
    ).to.throw('Malformed Header')
    expect(() =>
      deserializeMessageHeader(fixtures.base64MessageHeader())
    ).to.throw('Malformed Header: This blob may be base64 encoded.')
  })

  it('Precondition: suiteId must be a non-committing algorithm suite.', () => {
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    const suiteIdNotValidMessageHeader = fixtures.suiteIdNotValidMessageHeader()
    expect(() =>
      deserializeMessageHeader(suiteIdNotValidMessageHeader)
    ).to.throw('Unsupported algorithm suite.')
  })

  it('Postcondition: reservedBytes are defined as 0,0,0,0', () => {
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    const reservedBytesNoZeroMessageHeader =
      fixtures.reservedBytesNoZeroMessageHeader()
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
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    const reservedBytesNoZeroMessageHeader =
      fixtures.ivLengthMismatchMessageHeader()
    const headerIv = new Uint8Array(12).fill(1)
    const headerAuthTag = new Uint8Array(16).fill(2)
    const buffer = concatBuffers(
      reservedBytesNoZeroMessageHeader,
      headerIv,
      headerAuthTag
    )
    expect(() => deserializeMessageHeader(buffer)).to.throw('Malformed Header')
  })

  it('plumbs maxEncryptedDataKeys through', () => {
    const deserializeMessageHeader = deserializeHeaderV1Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })

    expect(() =>
      deserializeMessageHeader(fixtures.threeEdksMessagePartialHeaderV1(), {
        maxEncryptedDataKeys: 1,
      })
    ).to.throw('maxEncryptedDataKeys exceeded.')
  })
})
