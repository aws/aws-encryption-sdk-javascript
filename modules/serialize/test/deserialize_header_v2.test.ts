// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { deserializeHeaderV2Factory } from '../src/deserialize_header_v2'
import { decodeEncryptionContextFactory } from '../src/decode_encryption_context'
import { deserializeEncryptedDataKeysFactory } from '../src/deserialize_encrypted_data_keys'
import { serializeFactory } from '../src/serialize_factory'
import {
  MessageFormat,
  needs,
  WebCryptoAlgorithmSuite,
} from '@aws-crypto/material-management'
import * as fixtures from './fixtures'

const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString()
const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')

const decodeEncryptionContext = decodeEncryptionContextFactory(toUtf8)
const deserializeEncryptedDataKeys = deserializeEncryptedDataKeysFactory(toUtf8)

describe('deserializeMessageHeaderV2', () => {
  it('parses a simple message', () => {
    const deserializeMessageHeader = deserializeHeaderV2Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    const test = deserializeMessageHeader(fixtures.basicV2MessageHeader())
    needs(
      test && test.messageHeader.version === MessageFormat.V2,
      'failed to parse'
    )
    const { messageHeader } = test

    // Complete me
    expect(messageHeader.version).to.equal(MessageFormat.V2)
    expect(messageHeader.suiteId).to.equal(1144)
    expect(messageHeader.messageId.byteLength).to.equal(32)
  })

  it(`Check for early return (Postcondition): Not Enough Data. Need to have at least 37 bytes of data to begin parsing.
      Check for early return (Postcondition): Not Enough Data. Caller must buffer all of the context before we can parse the next section.
      Check for early return (Postcondition): Not Enough Data. Caller must buffer all of the encrypted data keys before we can parse the next section.
      Check for early return (Postcondition): Not Enough Data. Need to have the header auth section.`, () => {
    const deserializeMessageHeader = deserializeHeaderV2Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })
    // This is calculated from the header test above
    const buffer = fixtures.basicV2MessageHeader()

    // By testing every buffer size, we check every boundary condition for "not enough data"
    for (let i = 0; buffer.byteLength > i; i++) {
      const test = deserializeMessageHeader(buffer.slice(0, i))
      expect(test).to.eql(false)
    }
  })

  it('Precondition: version must be the required value.', () => {
    const deserializeMessageHeader = deserializeHeaderV2Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })

    // All 0 so the version number is clearly wrong
    const buffer = new Uint8Array(37)
    expect(() => deserializeMessageHeader(buffer)).to.throw('Malformed Header.')
    /* If a message is base64 encoded,
     * but instead of being decoded as base64
     * it is decoded as utf8,
     * the first UTF8 character of the base64 encoded string 'A'
     * will be `65`.
     * Encoding is hard,
     * so this helps customers get a better error message.
     */
    buffer[0] = 65
    expect(() => deserializeMessageHeader(buffer)).to.throw(
      'Malformed Header: This blob may be base64 encoded.'
    )
  })

  it('Precondition: suiteId must be a committing algorithm suite.', () => {
    const deserializeMessageHeader = deserializeHeaderV2Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })

    // All 0 so the version number is clearly wrong
    const buffer = new Uint8Array(37)
    buffer[0] = 2
    expect(() => deserializeMessageHeader(buffer)).to.throw(
      'Unsupported algorithm suite.'
    )
  })

  const deserializeHeaderV2Test = deserializeHeaderV2Factory({
    decodeEncryptionContext,
    deserializeEncryptedDataKeys,
    SdkSuite: WebCryptoAlgorithmSuite,
  })

  fixtures.compatibilityVectors().tests.forEach((test) => {
    const { header, ciphertext, comment } = test

    it(comment, () => {
      const value = deserializeHeaderV2Test(Buffer.from(header, 'base64'))
      expect(value).to.not.equal(false)
      const valueCiphertext = deserializeHeaderV2Test(
        Buffer.from(ciphertext, 'base64')
      )
      expect(valueCiphertext).to.not.equal(false)
    })
  })

  it('plumbs maxEncryptedDataKeys through', () => {
    const deserializeMessageHeader = deserializeHeaderV2Factory({
      decodeEncryptionContext,
      deserializeEncryptedDataKeys,
      SdkSuite: WebCryptoAlgorithmSuite,
    })

    expect(() =>
      deserializeMessageHeader(fixtures.threeEdksMessagePartialHeaderV2(), {
        maxEncryptedDataKeys: 1,
      })
    ).to.throw('maxEncryptedDataKeys exceeded.')
  })
})

describe('serializeMessageHeaderV2', () => {
  const deserializeHeaderV2Test = deserializeHeaderV2Factory({
    decodeEncryptionContext,
    deserializeEncryptedDataKeys,
    SdkSuite: WebCryptoAlgorithmSuite,
  })

  const { buildMessageHeader, serializeMessageHeader } =
    serializeFactory(fromUtf8)

  /* There is a compatibility bug in JS for encodeEncryptionContext.
   * The encryption context is sorted lexically.
   * It _should_ be binary sorted.
   * This is why the filter line exists.
   */
  fixtures
    .compatibilityVectors()
    .tests.filter((test) => Object.keys(test['encryption-context']).length < 2)
    .forEach((test) => {
      const { ciphertext, comment } = test
      /* For every successful vector,
       * I am testing that if the message was parsable,
       * then serializeMessageHeader should re-build
       * that message in to the same values...
       */
      it(comment, () => {
        const rawMessage = Buffer.from(ciphertext, 'base64')
        const baseHeader = deserializeHeaderV2Test(rawMessage)
        needs(
          baseHeader && baseHeader.messageHeader.version === MessageFormat.V2,
          'failed to parse'
        )

        // JS does not support serializing non-framed messages
        if (baseHeader.messageHeader.frameLength === 0) return
        const {
          encryptionContext,
          encryptedDataKeys,
          messageId,
          frameLength,
          suiteData,
        } = baseHeader.messageHeader

        const newMessageHeader = buildMessageHeader({
          encryptionContext,
          encryptedDataKeys,
          suite: baseHeader.algorithmSuite,
          messageId,
          frameLength,
          suiteData,
        })

        const test = serializeMessageHeader(newMessageHeader)
        /* The test vector has the whole header,
         * with the headerAuth section.
         * I want to verify just
         * the raw header part.
         */
        const rawHeader = rawMessage.slice(0, baseHeader.headerLength)

        expect(test).to.deep.equal(new Uint8Array(rawHeader))
      })
    })
})
