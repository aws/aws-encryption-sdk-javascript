// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { deserializeFactory } from '../src/deserialize_factory'
import { WebCryptoAlgorithmSuite } from '@aws-crypto/material-management'
import * as fixtures from './fixtures'
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString()
describe('decodeEncryptionContextFactory:decodeEncryptionContext', () => {
  it('returns context object', () => {
    const { decodeEncryptionContext } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    const contextSection = fixtures.basicEncryptionContext()

    const test = decodeEncryptionContext(contextSection.slice(2))
    expect(test).to.have.property('some').and.to.eql('public')
    expect(test)
      .to.have.property('information')
      .and.to.eql('\u00bd + \u00bc = \u00be')
  })

  it('Check for early return (Postcondition): The case of 0 length is defined as an empty object.', () => {
    const { decodeEncryptionContext } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )
    const test = decodeEncryptionContext(new Uint8Array(0))
    expect(test).to.be.deep.equal({})
  })

  it('Postcondition: Since the encryption context has a length, it must have pairs.', () => {
    const { decodeEncryptionContext } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    const badContextSection = fixtures.missingDataEncryptionContext().slice(2)
    expect(() => decodeEncryptionContext(badContextSection)).to.throw()
  })

  it('Postcondition: The byte length of the encodedEncryptionContext must match the readPos.', () => {
    const { decodeEncryptionContext } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    const badContextSection = fixtures.tooMuchDataEncryptionContext().slice(2)
    expect(() => decodeEncryptionContext(badContextSection)).to.throw()
  })

  it('Postcondition: The number of keys in the encryptionContext must match the pairsCount.', () => {
    const { decodeEncryptionContext } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    const badContextSection = fixtures.duplicateKeysEncryptionContext().slice(2)
    expect(() => decodeEncryptionContext(badContextSection)).to.throw()
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    const { decodeEncryptionContext } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    /* Create a Uint8Array that has an a valid FrameHeader but is proceeded by "invalid" bytes. (the Length part) */
    const buff = fixtures.basicEncryptionContext()
    expect(() => decodeEncryptionContext(buff)).to.throw()
    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(
      buff.buffer,
      2,
      buff.byteLength - 2
    )
    const test = decodeEncryptionContext(sharingArrayBuffer)
    expect(test).to.have.property('some').and.to.eql('public')
    expect(test)
      .to.have.property('information')
      .and.to.eql('\u00bd + \u00bc = \u00be')
  })

  it('Keys may be properties of Object.prototype, decodeEncryptionContext has to succeed', () => {
    const { decodeEncryptionContext } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    /* hasOwnProperty test vector */
    const encryptionContext = fixtures
      .hasOwnPropertyEncryptionContext()
      .slice(2)

    const test = decodeEncryptionContext(encryptionContext)
    expect(test).to.have.property('hasOwnProperty').and.to.eql('arbitraryValue')
  })
})
