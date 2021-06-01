// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { deserializeFactory } from '../src/deserialize_factory'
import { concatBuffers } from '../src'
import {
  WebCryptoAlgorithmSuite,
  EncryptedDataKey,
} from '@aws-crypto/material-management'
import * as fixtures from './fixtures'
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString()

describe('deserializeEncryptedDataKeysFactory:deserializeEncryptedDataKeys', () => {
  it('return EncryptedDataKey info', () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )
    const buffer = fixtures.encryptedDataKey()
    const test = deserializeEncryptedDataKeys(buffer, 0)
    if (!test) throw new Error('fail')
    expect(test)
      .to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)
    expect(test).to.have.property('readPos').and.to.eql(buffer.byteLength)

    const { encryptedDataKeys } = test

    expect(encryptedDataKeys[0]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[0].providerInfo).to.eql('firstKey')
    expect(encryptedDataKeys[0].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[0].rawInfo).to.deep.equal(
      new Uint8Array([102, 105, 114, 115, 116, 75, 101, 121])
    )
    expect(encryptedDataKeys[0].encryptedDataKey).to.deep.equal(
      new Uint8Array([1, 2, 3, 4, 5])
    )

    expect(encryptedDataKeys[1]).and.to.be.instanceOf(EncryptedDataKey)
    expect(encryptedDataKeys[1].providerInfo).to.eql('secondKey')
    expect(encryptedDataKeys[1].providerId).to.eql('½ + ¼ = ¾')
    expect(encryptedDataKeys[1].rawInfo).to.deep.equal(
      new Uint8Array([115, 101, 99, 111, 110, 100, 75, 101, 121])
    )
    expect(encryptedDataKeys[1].encryptedDataKey).to.deep.equal(
      new Uint8Array([6, 7, 8, 9, 0])
    )
  })

  it(`Check for early return (Postcondition): Need to have at least Uint16 (2) bytes of data.
      Check for early return (Postcondition): readElement will return false if there is not enough data.`, () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )
    const buffer = fixtures.encryptedDataKey()

    // By testing every buffer size, we check every boundary condition for "not enough data"
    for (let i = 0; buffer.byteLength > i; i++) {
      const test = deserializeEncryptedDataKeys(buffer.slice(0, i), 0)
      expect(test).to.eql(false)
    }
  })

  it('Precondition: There must be at least 1 EncryptedDataKey element.', () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )
    const buffer = new Uint8Array(2)

    expect(() => deserializeEncryptedDataKeys(buffer, 0)).to.throw()
  })

  it('Precondition: encryptedDataKeysCount must not exceed maxEncryptedDataKeys.', () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )
    const maxEncryptedDataKeys = 3
    for (const numKeys of [2, 3, 4]) {
      const buffer = new Uint8Array([0, numKeys])
      const test = () =>
        deserializeEncryptedDataKeys(buffer, 0, { maxEncryptedDataKeys })
      if (numKeys <= maxEncryptedDataKeys) {
        test()
      } else {
        expect(test).to.throw('maxEncryptedDataKeys exceeded.')
      }
    }
  })

  it('Precondition: deserializeEncryptedDataKeys needs a valid maxEncryptedDataKeys.', () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )
    const buffer = fixtures.encryptedDataKey()
    expect(() =>
      deserializeEncryptedDataKeys(buffer, 0, { maxEncryptedDataKeys: 0 })
    ).to.throw('Invalid maxEncryptedDataKeys value.')
  })

  it('Precondition: startPos must be within the byte length of the buffer given.', () => {
    const { deserializeEncryptedDataKeys } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )
    const buffer = new Uint8Array(10)

    expect(() =>
      deserializeEncryptedDataKeys(buffer, buffer.byteLength + 1)
    ).to.throw()
    expect(() => deserializeEncryptedDataKeys(buffer, -1)).to.throw()
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    /* Create a Uint8Array that has an a valid FrameHeader but is proceeded by "invalid" bytes. */
    const { deserializeEncryptedDataKeys } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )
    const buffer = concatBuffers(new Uint8Array(5), fixtures.encryptedDataKey())
    expect(() => deserializeEncryptedDataKeys(buffer, 0)).to.throw()
    // Now we verify that the if we read from after the "invalid" section everything is OK.
    const verify = deserializeEncryptedDataKeys(buffer, 5)
    expect(verify)
      .to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)
    expect(verify).to.have.property('readPos').and.to.eql(buffer.byteLength)

    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(
      buffer.buffer,
      5,
      buffer.byteLength - 5
    )
    const test = deserializeEncryptedDataKeys(sharingArrayBuffer, 0)
    if (!test) throw new Error('fail')
    expect(test)
      .to.have.property('encryptedDataKeys')
      .and.to.be.an('Array')
      .and.to.have.lengthOf(2)
    expect(test)
      .to.have.property('readPos')
      .and.to.eql(sharingArrayBuffer.byteLength)

    const { encryptedDataKeys } = test

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
  })
})
