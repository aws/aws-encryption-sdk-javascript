// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { aadFactory } from '../src/aad_factory'
import { ContentType, ContentAADString } from '../src/identifiers'

describe('aadFactory:messageAADContentString', () => {
  it('should return framed string for a non-final-frame', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
    const { messageAADContentString } = aadFactory(fromUtf8)
    const contentType = ContentType.FRAMED_DATA
    const isFinalFrame = false
    expect(messageAADContentString({ contentType, isFinalFrame })).to.eql(
      ContentAADString.FRAME_STRING_ID
    )
  })
  it('should return final framed string for a final-frame', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
    const { messageAADContentString } = aadFactory(fromUtf8)
    const contentType = ContentType.FRAMED_DATA
    const isFinalFrame = true
    expect(messageAADContentString({ contentType, isFinalFrame })).to.eql(
      ContentAADString.FINAL_FRAME_STRING_ID
    )
  })

  it('should return non-framed string for a non-frame case', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
    const { messageAADContentString } = aadFactory(fromUtf8)
    const contentType = ContentType.NO_FRAMING
    expect(messageAADContentString({ contentType, isFinalFrame: true })).to.eql(
      ContentAADString.NON_FRAMED_STRING_ID
    )
    expect(
      messageAADContentString({ contentType, isFinalFrame: false })
    ).to.eql(ContentAADString.NON_FRAMED_STRING_ID)
  })

  it('should throw for an unrecognized frame types', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
    const { messageAADContentString } = aadFactory(fromUtf8)
    const test = () =>
      messageAADContentString({
        contentType: 'something',
        isFinalFrame: true,
      } as any)
    expect(test).to.throw()
  })
})

describe('aadFactory:messageAAD', () => {
  it('should concatenate data', () => {
    const fromUtf8 = (input: string) => {
      expect(input).to.eql(ContentAADString.NON_FRAMED_STRING_ID)
      return Buffer.from(input)
    }
    const { messageAAD } = aadFactory(fromUtf8)

    const messageId = Buffer.alloc(16, 1)

    const test = messageAAD(
      messageId,
      ContentAADString.NON_FRAMED_STRING_ID,
      1,
      100
    )

    expect(test).to.be.instanceof(Uint8Array)
    const length = 16 + ContentAADString.NON_FRAMED_STRING_ID.length + 4 + 8
    expect(test.byteLength).to.eql(length)

    expect(test).to.deep.equal(
      new Uint8Array([
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 65, 87, 83, 75, 77, 83,
        69, 110, 99, 114, 121, 112, 116, 105, 111, 110, 67, 108, 105, 101, 110,
        116, 32, 83, 105, 110, 103, 108, 101, 32, 66, 108, 111, 99, 107, 0, 0,
        0, 1, 0, 0, 0, 0, 0, 0, 0, 100,
      ])
    )
  })
})
