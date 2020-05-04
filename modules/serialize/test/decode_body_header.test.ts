// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  decodeFrameBodyHeader,
  decodeNonFrameBodyHeader,
  decodeBodyHeader,
  decodeFinalFrameBodyHeader,
} from '../src/decode_body_header'
import { concatBuffers } from '../src'
import * as fixtures from './fixtures'
import { ContentType } from '../src/identifiers'

describe('decodeBodyHeader', () => {
  it('calls decodeFrameBodyHeader', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const test = decodeBodyHeader(fixtures.basicFrameHeader(), headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
  })

  it('calls decodeNonFrameBodyHeader', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const test = decodeBodyHeader(fixtures.basicNonFrameHeader(), headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.contentType).to.eql(ContentType.NO_FRAMING)
  })

  it('Precondition: The contentType must be a supported format.', () => {
    const headerInfo = {
      messageHeader: {
        contentType: 'does not exist',
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    expect(() =>
      decodeBodyHeader(fixtures.basicNonFrameHeader(), headerInfo, 0)
    ).to.throw('Unknown contentType')
  })
})

describe('decodeFrameBodyHeader', () => {
  it('return frame header', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const test = decodeFrameBodyHeader(
      fixtures.basicFrameHeader(),
      headerInfo,
      0
    )
    if (!test) throw new Error('failure')
    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.readPos).to.eql(16)
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(false)
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
  })

  it('return final frame header', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const test = decodeFrameBodyHeader(
      fixtures.finalFrameHeader(),
      headerInfo,
      0
    )
    if (!test) throw new Error('failure')
    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.readPos).to.eql(24)
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(true)
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
  })

  it('Precondition: The contentType must be FRAMED_DATA.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: 'not FRAMED_DATA',
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    expect(() =>
      decodeFrameBodyHeader(fixtures.basicFrameHeader(), headerInfo, 0)
    ).to.throw('Unknown contentType')
  })

  it('Check for early return (Postcondition): There must be enough data to decodeFrameBodyHeader.', () => {
    const frameHeader = fixtures.basicFrameHeader()
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    for (let i = 0; frameHeader.byteLength > i; i++) {
      const test = decodeFrameBodyHeader(frameHeader.slice(0, i), headerInfo, 0)
      expect(test).to.eql(false)
    }
  })

  it('return frame header from readPos', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const buffer = concatBuffers(
      new Uint8Array(10), // pre
      fixtures.basicFrameHeader(),
      new Uint8Array(10) // post
    )

    const test = decodeFrameBodyHeader(buffer, headerInfo, 10)
    if (!test) throw new Error('failure')
    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.readPos).to.eql(26)
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(false)
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
  })

  it('return false for partial basic frame from readPos', () => {
    const buffer = concatBuffers(
      new Uint8Array(10),
      fixtures.basicFrameHeader()
    )
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    for (let i = 10; buffer.byteLength - 1 > i; i++) {
      const test = decodeFrameBodyHeader(buffer.slice(0, i), headerInfo, 10)
      expect(test).to.eql(false)
    }
  })

  it('return false for partial frame from readPos', () => {
    const buffer = concatBuffers(
      new Uint8Array(10),
      fixtures.finalFrameHeader()
    )
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    for (let i = 10; buffer.byteLength > i; i++) {
      const test = decodeFrameBodyHeader(buffer.slice(0, i), headerInfo, 10)
      expect(test).to.eql(false)
    }
  })

  it('Precondition: decodeFrameBodyHeader readPos must be within the byte length of the buffer given.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const buffer = fixtures.basicFrameHeader()
    expect(() =>
      decodeFrameBodyHeader(buffer, headerInfo, buffer.byteLength + 1)
    ).to.throw()
    expect(() => decodeFrameBodyHeader(buffer, headerInfo, -1)).to.throw()
  })

  it('Postcondition: decodeFrameBodyHeader sequenceNumber must be greater than 0.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    expect(() =>
      decodeFrameBodyHeader(
        fixtures.invalidSequenceNumberFrameHeader(),
        headerInfo,
        0
      )
    ).to.throw('Malformed sequenceNumber.')
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    /* Create a Uint8Array that has an a valid FrameHeader but is proceeded by "invalid" bytes. */
    const buff = concatBuffers(new Uint8Array(5), fixtures.basicFrameHeader())
    expect(() => decodeFrameBodyHeader(buff, headerInfo, 0)).to.throw()
    // Now we verify that the if we read from after the "invalid" section everything is OK.
    const verify = decodeFrameBodyHeader(buff, headerInfo, 5)
    if (!verify) throw new Error('failure')
    expect(verify.sequenceNumber).to.eql(1)
    expect(verify.iv).to.eql(fixtures.basicFrameIV())
    expect(verify.readPos).to.eql(buff.byteLength)
    expect(verify.tagLength).to.eql(16)
    expect(verify.isFinalFrame).to.eql(false)
    expect(verify.contentType).to.eql(ContentType.FRAMED_DATA)

    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(
      buff.buffer,
      5,
      buff.byteLength - 5
    )
    const test = decodeFrameBodyHeader(sharingArrayBuffer, headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.readPos).to.eql(sharingArrayBuffer.byteLength)
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(false)
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
  })
})

describe('decodeFinalFrameBodyHeader', () => {
  it('return final frame header from readPos', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any
    const buffer = concatBuffers(
      new Uint8Array(10), // pre
      fixtures.finalFrameHeader(),
      new Uint8Array(10) // post
    )

    const test = decodeFinalFrameBodyHeader(buffer, headerInfo, 10)
    if (!test) throw new Error('failure')
    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.readPos).to.eql(34)
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(true)
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
    expect(test.contentLength).to.eql(999)
  })

  it('The final frame can be 0 length.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any
    const buffer = fixtures.finalFrameHeaderZeroBytes()

    const test = decodeFinalFrameBodyHeader(buffer, headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(true)
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
    expect(test.contentLength).to.eql(0)
  })

  it('Precondition: The contentType must be FRAMED_DATA to be a Final Frame.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: 'not FRAMED_DATA',
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    expect(() =>
      decodeFinalFrameBodyHeader(fixtures.finalFrameHeader(), headerInfo, 0)
    ).to.throw('Unknown contentType')
  })

  it('Precondition: decodeFinalFrameBodyHeader readPos must be within the byte length of the buffer given.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const buffer = fixtures.finalFrameHeader()
    expect(() =>
      decodeFinalFrameBodyHeader(buffer, headerInfo, buffer.byteLength + 1)
    ).to.throw('readPos out of bounds.')
    expect(() => decodeFinalFrameBodyHeader(buffer, headerInfo, -1)).to.throw(
      'readPos out of bounds.'
    )
  })

  it('Postcondition: sequenceEnd must be SEQUENCE_NUMBER_END.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const buffer = fixtures.invalidSequenceEndFinalFrameHeader()
    expect(() => decodeFinalFrameBodyHeader(buffer, headerInfo, 0)).to.throw(
      'Malformed final frame: Invalid sequence number end value'
    )
  })

  it('Postcondition: decodeFinalFrameBodyHeader sequenceNumber must be greater than 0.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const buffer = fixtures.invalidSequenceNumberFinalFrameHeader()
    expect(() => decodeFinalFrameBodyHeader(buffer, headerInfo, 0)).to.throw(
      'Malformed sequenceNumber.'
    )
  })

  it('Check for early return (Postcondition): There must be enough data to decodeFinalFrameBodyHeader.', () => {
    const frameHeader = fixtures.finalFrameHeader()
    const headerInfo = {
      messageHeader: {
        frameLength: 999,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    for (let i = 0; frameHeader.byteLength > i; i++) {
      const test = decodeFinalFrameBodyHeader(
        frameHeader.slice(0, i),
        headerInfo,
        0
      )
      expect(test).to.eql(false)
    }
  })

  it('Postcondition: The final frame MUST NOT exceed the frameLength.', () => {
    const headerInfo = {
      messageHeader: {
        // The content length in this final frame is 999
        // So I set the frame length to less than this
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any
    const buffer = fixtures.finalFrameHeader()

    expect(() => decodeFinalFrameBodyHeader(buffer, headerInfo, 0)).to.throw(
      'Final frame length exceeds frame length.'
    )
  })
})

describe('decodeNonFrameBodyHeader', () => {
  it('return non frame header', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const buffer = fixtures.basicNonFrameHeader()
    const test = decodeNonFrameBodyHeader(buffer, headerInfo, 0)
    if (!test) throw new Error('failure')

    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.readPos).to.eql(20)
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(true)
    expect(test.contentType).to.eql(ContentType.NO_FRAMING)
    expect(test.contentLength).to.eql(0)
  })

  it('Precondition: The contentType must be NO_FRAMING.', () => {
    const headerInfo = {
      messageHeader: {
        contentType: 'not NO_FRAMING',
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const buffer = fixtures.basicNonFrameHeader()
    expect(() => decodeNonFrameBodyHeader(buffer, headerInfo, 0)).to.throw(
      'Unknown contentType'
    )
  })

  it('Check for early return (Postcondition): There must be enough data to decodeNonFrameBodyHeader.', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const frameHeader = fixtures.basicNonFrameHeader()

    for (let i = 0; frameHeader.byteLength > i; i++) {
      const test = decodeNonFrameBodyHeader(
        frameHeader.slice(0, i),
        headerInfo,
        0
      )
      expect(test).to.eql(false)
    }
  })

  it('Precondition: decodeNonFrameBodyHeader readPos must be within the byte length of the buffer given.', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    const buffer = fixtures.basicNonFrameHeader()
    expect(() =>
      decodeNonFrameBodyHeader(buffer, headerInfo, buffer.byteLength + 1)
    ).to.throw()
    expect(() => decodeNonFrameBodyHeader(buffer, headerInfo, -1)).to.throw()
  })

  it('Postcondition: Non-framed content length MUST NOT exceed AES-GCM safe limits.', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    expect(() =>
      decodeNonFrameBodyHeader(
        fixtures.invalidNonFrameHeaderContentLengthExcedsLimits(),
        headerInfo,
        0
      )
    ).to.throw('Content length out of bounds.')
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING,
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16,
      },
    } as any

    /* Create a Uint8Array that has an a valid FrameHeader but is proceeded by "invalid" bytes. */
    const buff = concatBuffers(
      new Uint8Array(5),
      fixtures.basicNonFrameHeader()
    )
    const shouldFail = decodeNonFrameBodyHeader(buff, headerInfo, 0)
    if (!shouldFail) throw new Error('failure')
    expect(shouldFail.iv).to.not.eql(fixtures.basicFrameIV())
    // Now we verify that the if we read from after the "invalid" section everything is OK.
    const verify = decodeNonFrameBodyHeader(buff, headerInfo, 5)
    if (!verify) throw new Error('failure')
    expect(verify.iv).to.eql(fixtures.basicFrameIV())

    /* Given this I can use this to construct a new view of part of the
     * ArrayBuffer to simulate a large ArrayBuffer that is sliced
     * into parts for efficiency. */
    const sharingArrayBuffer = new Uint8Array(
      buff.buffer,
      5,
      buff.byteLength - 5
    )
    const test = decodeNonFrameBodyHeader(sharingArrayBuffer, headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.iv).to.eql(fixtures.basicFrameIV())
  })
})
