// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  getFramedEncryptStream,
  getEncryptFrame,
} from '../src/framed_encrypt_stream'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
} from '@aws-crypto/material-management-node'

const suite = new NodeAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
)

chai.use(chaiAsPromised)
const { expect } = chai

describe('getFramedEncryptStream', () => {
  it('can be created', () => {
    const getCipher: any = () => {}
    const test = getFramedEncryptStream(
      getCipher,
      {} as any,
      () => {},
      {} as any
    )
    expect(test._transform).is.a('function')
  })

  it('Precondition: plaintextLength must be within bounds.', () => {
    const getCipher: any = () => {}
    expect(() =>
      getFramedEncryptStream(getCipher, {} as any, () => {}, {
        plaintextLength: -1,
        suite,
      })
    ).to.throw(Error, 'plaintextLength out of bounds.')
    expect(() =>
      getFramedEncryptStream(getCipher, {} as any, () => {}, {
        plaintextLength: Number.MAX_SAFE_INTEGER + 1,
        suite,
      })
    ).to.throw(Error, 'plaintextLength out of bounds.')

    /* Math is hard.
     * I want to make sure that I don't have an errant off by 1 error.
     */
    expect(() =>
      getFramedEncryptStream(getCipher, {} as any, () => {}, {
        plaintextLength: Number.MAX_SAFE_INTEGER,
        suite,
      })
    ).to.not.throw(Error)
  })

  it('Precondition: Must not process more than plaintextLength.', () => {
    const getCipher: any = () => {}
    const test = getFramedEncryptStream(getCipher, {} as any, () => {}, {
      plaintextLength: 8,
      suite,
    })

    expect(() =>
      test._transform(Buffer.from(Array(9)), 'binary', () => {})
    ).to.throw(Error, 'Encrypted data exceeded plaintextLength.')
  })

  it('Check for early return (Postcondition): Have not accumulated a frame.', () => {
    const getCipher: any = () => {}
    const frameLength = 10
    const test = getFramedEncryptStream(
      getCipher,
      { frameLength } as any,
      () => {},
      {} as any
    )

    let called = false
    test._transform(Buffer.from(Array(9)), 'binary', () => {
      called = true
    })

    expect(called).to.equal(true)
  })
})

describe('getEncryptFrame', () => {
  it('can return an EncryptFrame', () => {
    const input = {
      pendingFrame: {
        content: [Buffer.from([1, 2, 3, 4, 5])],
        contentLength: 5,
        sequenceNumber: 1,
      },
      isFinalFrame: false,
      getCipher: () => ({ setAAD: () => {} } as any),
      messageHeader: {
        frameLength: 5,
        contentType: 2,
        messageId: Buffer.from([]),
        headerIvLength: 12 as const,
        version: 1,
        type: 12,
        suiteId: 1,
        encryptionContext: {},
        encryptedDataKeys: [],
      },
      suite,
    }
    const test1 = getEncryptFrame(input)
    expect(test1.content).to.equal(input.pendingFrame.content)
    expect(test1.isFinalFrame).to.equal(input.isFinalFrame)

    // Just a quick flip to make sure...
    input.isFinalFrame = true
    const test2 = getEncryptFrame(input)
    expect(test2.content).to.equal(input.pendingFrame.content)
    expect(test2.isFinalFrame).to.equal(input.isFinalFrame)
  })

  it('Precondition: The content length MUST correlate with the frameLength.', () => {
    const inputFinalFrameToLarge = {
      pendingFrame: {
        content: [Buffer.from([1, 2, 3, 4, 5, 6])],
        // This exceeds the frameLength below
        contentLength: 6,
        sequenceNumber: 1,
      },
      isFinalFrame: true,
      getCipher: () => ({ setAAD: () => {} } as any),
      messageHeader: {
        frameLength: 5,
        contentType: 2,
        messageId: Buffer.from([]),
        headerIvLength: 12 as const,
        version: 1,
        type: 12,
        suiteId: 1,
        encryptionContext: {},
        encryptedDataKeys: [],
      },
      suite,
    }

    expect(() => getEncryptFrame(inputFinalFrameToLarge)).to.throw(
      'Malformed frame length and content length:'
    )

    const inputFrame = {
      pendingFrame: {
        content: [Buffer.from([1, 2, 3, 4, 5])],
        contentLength: 5,
        sequenceNumber: 1,
      },
      isFinalFrame: false,
      getCipher: () => ({ setAAD: () => {} } as any),
      messageHeader: {
        frameLength: 5,
        contentType: 2,
        messageId: Buffer.from([]),
        headerIvLength: 12 as const,
        version: 1,
        type: 12,
        suiteId: 1,
        encryptionContext: {},
        encryptedDataKeys: [],
      },
      suite,
    }

    // Make sure that it must be equal as long as we are here...
    inputFrame.pendingFrame.contentLength = 4
    expect(() => getEncryptFrame(inputFrame)).to.throw(
      'Malformed frame length and content length:'
    )
    inputFrame.pendingFrame.contentLength = 6
    expect(() => getEncryptFrame(inputFrame)).to.throw(
      'Malformed frame length and content length:'
    )
  })
})
