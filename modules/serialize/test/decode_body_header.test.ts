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
import { decodeFrameBodyHeader, decodeNonFrameBodyHeader, decodeBodyHeader } from '../src/decode_body_header'
import { concatBuffers } from '../src'
import * as fixtures from './fixtures'
import { ContentType } from '../src/identifiers'

describe('decodeBodyHeader', () => {
  it('calls decodeFrameBodyHeader', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    const test = decodeBodyHeader(fixtures.basicFrameHeader(), headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
  })

  it('calls decodeNonFrameBodyHeader', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    const test = decodeBodyHeader(fixtures.basicNonFrameHeader(), headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.contentType).to.eql(ContentType.NO_FRAMING)
  })

  it('throws for unknown contentType', () => {
    const headerInfo = {
      messageHeader: {
        contentType: 'does not exist'
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    expect(() => decodeBodyHeader(fixtures.basicNonFrameHeader(), headerInfo, 0)).to.throw()
  })
})

describe('decodeFrameBodyHeader', () => {
  it('return frame header', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    const test = decodeFrameBodyHeader(fixtures.basicFrameHeader(), headerInfo, 0)
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
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    const test = decodeFrameBodyHeader(fixtures.finalFrameHeader(), headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.readPos).to.eql(24)
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(true)
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
  })

  it('Precondition: There must be enough data to parse. for partial basic frame', () => {
    const frameHeader = fixtures.basicFrameHeader()
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    for (let i = 0; frameHeader.byteLength > i; i++) {
      const test = decodeFrameBodyHeader(frameHeader.slice(0, i), headerInfo, 0)
      expect(test).to.eql(false)
    }
  })

  it('Precondition: There must be enough data to parse. for partial final frame', () => {
    const frameHeader = fixtures.finalFrameHeader()
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
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
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
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

  it('return final frame header from readPos', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any
    const buffer = concatBuffers(
      new Uint8Array(10), // pre
      fixtures.finalFrameHeader(),
      new Uint8Array(10) // post
    )

    const test = decodeFrameBodyHeader(buffer, headerInfo, 10)
    if (!test) throw new Error('failure')
    expect(test.sequenceNumber).to.eql(1)
    expect(test.iv).to.eql(fixtures.basicFrameIV())
    expect(test.readPos).to.eql(34)
    expect(test.tagLength).to.eql(16)
    expect(test.isFinalFrame).to.eql(true)
    expect(test.contentType).to.eql(ContentType.FRAMED_DATA)
  })

  it('return undefined for partial basic frame from readPos', () => {
    const buffer = concatBuffers(new Uint8Array(10), fixtures.basicFrameHeader())
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    for (let i = 10; buffer.byteLength - 1 > i; i++) {
      const test = decodeFrameBodyHeader(buffer.slice(0, i), headerInfo, 10)
      expect(test).to.eql(false)
    }
  })

  it('return undefined for partial frame from readPos', () => {
    const buffer = concatBuffers(new Uint8Array(10), fixtures.finalFrameHeader())
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    for (let i = 10; buffer.byteLength > i; i++) {
      const test = decodeFrameBodyHeader(buffer.slice(0, i), headerInfo, 10)
      expect(test).to.eql(false)
    }
  })

  it('Precondition: readPos must be within the byte length of the buffer given.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    const buffer = fixtures.basicFrameHeader()
    expect(() => decodeFrameBodyHeader(buffer, headerInfo, buffer.byteLength + 1)).to.throw()
    expect(() => decodeFrameBodyHeader(buffer, headerInfo, -1)).to.throw()
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    const headerInfo = {
      messageHeader: {
        frameLength: 99,
        contentType: ContentType.FRAMED_DATA
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
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
    const sharingArrayBuffer = new Uint8Array(buff.buffer, 5, buff.byteLength - 5)
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

describe('decodeNonFrameBodyHeader', () => {
  it('return non frame header', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
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
  })

  it('Precondition: There must be enough data to parse. for partial non frame', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    const frameHeader = fixtures.basicNonFrameHeader()

    for (let i = 0; frameHeader.byteLength > i; i++) {
      const test = decodeNonFrameBodyHeader(frameHeader.slice(0, i), headerInfo, 0)
      expect(test).to.eql(false)
    }
  })

  it('Precondition: readPos must be within the byte length of the buffer given.', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    const buffer = fixtures.basicNonFrameHeader()
    expect(() => decodeNonFrameBodyHeader(buffer, headerInfo, buffer.byteLength + 1)).to.throw()
    expect(() => decodeNonFrameBodyHeader(buffer, headerInfo, -1)).to.throw()
  })

  it('ArrayBuffer for a Uint8Array or Buffer may be larger than the Uint8Array or Buffer that it is a view over is.', () => {
    const headerInfo = {
      messageHeader: {
        contentType: ContentType.NO_FRAMING
      },
      algorithmSuite: {
        ivLength: 12,
        tagLength: 16
      }
    } as any

    /* Create a Uint8Array that has an a valid FrameHeader but is proceeded by "invalid" bytes. */
    const buff = concatBuffers(new Uint8Array(5), fixtures.basicNonFrameHeader())
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
    const sharingArrayBuffer = new Uint8Array(buff.buffer, 5, buff.byteLength - 5)
    const test = decodeNonFrameBodyHeader(sharingArrayBuffer, headerInfo, 0)
    if (!test) throw new Error('failure')
    expect(test.iv).to.eql(fixtures.basicFrameIV())
  })
})
