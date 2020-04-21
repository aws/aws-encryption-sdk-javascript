// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { getDecipherStream } from '../src//decipher_stream'
import { VerifyStream } from '../src/verify_stream'
import { ContentType } from '@aws-crypto/serialize'
import from from 'from2'

describe('getDecipherStream', () => {
  it('Precondition: The source must be a VerifyStream to emit the required events.', () => {
    const test = getDecipherStream()
    const notVerifyStream = from(() => {}) as any
    expect(() => notVerifyStream.pipe(test)).to.throw('Unsupported source')
  })

  it('Precondition: decipherInfo must be set before BodyInfo is sent.', () => {
    const test = getDecipherStream()
    expect(() => test._onBodyHeader({} as any)).to.throw('Malformed State.')
  })

  it('Precondition: Ciphertext must not be flowing before a BodyHeader is processed.', () => {
    const verifyStream = new VerifyStream({})
    const test = getDecipherStream()
    verifyStream.pipe(test)
    verifyStream.emit('DecipherInfo', {
      messageId: Buffer.from(Array(16)),
      contentType: ContentType.FRAMED_DATA,
      iv: Buffer.from(Array(12)),
      getDecipher: () => ({
        setAAD() {
          // set decipher to a true-ish value for test
          return true
        },
      }),
    })
    const bodyInfo = {
      contentLength: 123,
      iv: Buffer.from(Array(12)),
      sequenceNumber: 1,
      isFinalFrame: false,
    }
    test._onBodyHeader(bodyInfo)

    // The basis of this test is that 2 bodyInfo events must not
    // happen without a AuthTag in between
    expect(() => test._onBodyHeader(bodyInfo)).to.throw('Malformed State.')
  })

  it('Precondition: BodyHeader must be parsed before frame data.', () => {
    const test = getDecipherStream()
    expect(() =>
      test._transform(Buffer.from([1]), 'binary', () => {})
    ).to.throw('Malformed State.')
  })

  it('Precondition: Only content should be transformed, so the lengths must always match.', () => {
    const verifyStream = new VerifyStream({})
    const test = getDecipherStream()
    verifyStream.pipe(test)
    verifyStream.emit('DecipherInfo', {
      messageId: Buffer.from(Array(16)),
      contentType: ContentType.FRAMED_DATA,
      iv: Buffer.from(Array(12)),
      getDecipher: () => ({
        setAAD() {
          // set decipher to a true-ish value for test
          return true
        },
      }),
    })
    const bodyInfo = {
      contentLength: 0,
      iv: Buffer.from(Array(12)),
      sequenceNumber: 1,
      isFinalFrame: false,
    }
    test._onBodyHeader(bodyInfo)

    expect(() =>
      test._transform(Buffer.from([1]), 'binary', () => {})
    ).to.throw('Lengths do not match')
  })

  it('Precondition: _onAuthTag must be called only after a frame has been accumulated.', async () => {
    const verifyStream = new VerifyStream({})
    const test = getDecipherStream()
    verifyStream.pipe(test)
    verifyStream.emit('DecipherInfo', {
      messageId: Buffer.from(Array(16)),
      contentType: ContentType.FRAMED_DATA,
      iv: Buffer.from(Array(12)),
      getDecipher: () => ({
        setAAD() {
          // set decipher to a true-ish value for test
          return true
        },
      }),
    })
    const bodyInfo = {
      contentLength: 10,
      iv: Buffer.from(Array(12)),
      sequenceNumber: 1,
      isFinalFrame: false,
    }
    test._onBodyHeader(bodyInfo)

    await expect(test._onAuthTag(Buffer.from([]), () => {})).to.rejectedWith(
      Error,
      'AuthTag before frame.'
    )
  })
})
