import BN from 'bn.js'
import {ContentType, SequenceIdentifier} from './identifiers'
import {HeaderInfo, BodyHeader, FrameBodyHeader, NonFrameBodyHeader} from './types'

export function decodeBodyHeader(buffer: Uint8Array, headerInfo: HeaderInfo, readPos: number): BodyHeader|undefined {
  switch (headerInfo.messageHeader.contentType) {
    case ContentType.FRAMED_DATA:
      return decodeFrameBodyHeader(buffer, headerInfo, readPos)
    case ContentType.NO_FRAMING:
      return decodeNonFrameBodyHeader(buffer, headerInfo, readPos)
  }
  throw new Error('Unknown format')
}

// decodeFrameHeader is going to support non-framed parsing....
export function decodeFrameBodyHeader(buffer: Uint8Array, headerInfo: HeaderInfo, readPos: number): FrameBodyHeader|undefined {
  const {frameLength} = headerInfo.messageHeader
  const {ivLength, tagLength} = headerInfo.algorithmSuite

  const dataView = new DataView(buffer.buffer)

  if (4 + ivLength + readPos > dataView.byteLength) return

  if (dataView.getUint32(readPos) !== SequenceIdentifier.SEQUENCE_NUMBER_END) {
    const sequenceNumber = dataView.getUint32(readPos)
    const iv = buffer.slice(readPos += 4, readPos += ivLength)
    return {
      sequenceNumber,
      iv,
      contentLength: frameLength,
      readPos,
      tagLength,
      isFinalFrame: false,
      contentType: ContentType.FRAMED_DATA
    }
  }

  if (4 + 4 + ivLength + 4 + readPos> dataView.byteLength) return

  if (dataView.getUint32(readPos) === SequenceIdentifier.SEQUENCE_NUMBER_END) {
    const sequenceNumber = dataView.getUint32(readPos += 4)
    const iv = buffer.slice(readPos += 4, readPos += ivLength)
    const contentLength = dataView.getUint32(readPos)
    return {
      sequenceNumber,
      iv,
      contentLength,
      readPos: readPos + 4,
      tagLength,
      isFinalFrame: true,
      contentType: ContentType.FRAMED_DATA
    }
  }

  throw new Error('Unknown format')
}

export function decodeNonFrameBodyHeader(buffer: Uint8Array, headerInfo: HeaderInfo, readPos: number): NonFrameBodyHeader|undefined {
  const {ivLength, tagLength} = headerInfo.algorithmSuite

  const dataView = new DataView(buffer.buffer)

  if (ivLength + 8 + readPos > dataView.byteLength) return

  if (dataView.getUint32(readPos) !== SequenceIdentifier.SEQUENCE_NUMBER_END) {
    const iv = buffer.slice(readPos, readPos += ivLength)
    const contentLengthBuff = buffer.slice(readPos, readPos += 8)
    const contentLengthBN = new BN([...contentLengthBuff], 16, 'be')
    // This will throw if the number is larger than Number.MAX_SAFE_INTEGER.
    // i.e. a 53 bit number
    const contentLength = contentLengthBN.toNumber()
    return {
      sequenceNumber: 1,
      iv,
      contentLength,
      readPos,
      tagLength,
      isFinalFrame: true,
      contentType: ContentType.NO_FRAMING
    }
  }

  throw new Error('Unknown format')
}
