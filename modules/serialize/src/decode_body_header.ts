// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import BN from 'bn.js'
import { ContentType, SequenceIdentifier, Maximum } from './identifiers'
import {
  HeaderInfo,
  BodyHeader,
  FrameBodyHeader,
  NonFrameBodyHeader,
} from './types'
import { needs } from '@aws-crypto/material-management'

/*
 * This public interface for reading the BodyHeader format is provided for
 * the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other
 * than the Encryption SDK for JavaScript.
 *
 * See:
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#body-framing
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#body-no-framing
 */

/**
 * decodeBodyHeader
 *
 * I need to be able to parse the BodyHeader, but since the data may be streamed
 * I may not have all the data yet.  The caller is expected to maintain and append
 * to the buffer and call this function with the same readPos until the function
 * returns a BodyHeader.
 *
 * @param buffer Uint8Array
 * @param headerInfo HeaderInfo
 * @param readPos number
 * @returns BodyHeader|false
 */
export function decodeBodyHeader(
  buffer: Uint8Array,
  headerInfo: HeaderInfo,
  readPos: number
): BodyHeader | false {
  /* Precondition: The contentType must be a supported format. */
  needs(
    ContentType[headerInfo.messageHeader.contentType],
    'Unknown contentType'
  )

  switch (headerInfo.messageHeader.contentType) {
    case ContentType.FRAMED_DATA:
      return decodeFrameBodyHeader(buffer, headerInfo, readPos)
    case ContentType.NO_FRAMING:
      return decodeNonFrameBodyHeader(buffer, headerInfo, readPos)
  }
  return false
}

/**
 *  Exported for testing.  Used by decodeBodyHeader to compose a complete solution.
 * @param buffer Uint8Array
 * @param headerInfo HeaderInfo
 * @param readPos number
 */
export function decodeFrameBodyHeader(
  buffer: Uint8Array,
  headerInfo: HeaderInfo,
  readPos: number
): FrameBodyHeader | false {
  /* Precondition: The contentType must be FRAMED_DATA. */
  needs(
    ContentType.FRAMED_DATA === headerInfo.messageHeader.contentType,
    'Unknown contentType'
  )

  const { frameLength } = headerInfo.messageHeader
  const { ivLength, tagLength } = headerInfo.algorithmSuite

  /* Uint8Array is a view on top of the underlying ArrayBuffer.
   * This means that raw underlying memory stored in the ArrayBuffer
   * may be larger than the Uint8Array.  This is especially true of
   * the Node.js Buffer object.  The offset and length *must* be
   * passed to the DataView otherwise I will get unexpected results.
   */
  const dataView = new DataView(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength
  )

  /* Precondition: decodeFrameBodyHeader readPos must be within the byte length of the buffer given. */
  needs(
    dataView.byteLength >= readPos && readPos >= 0,
    'readPos out of bounds.'
  )

  /* Check for early return (Postcondition): There must be enough data to decodeFrameBodyHeader.
   * The format expressed here is
   * SequenceIdentifier: Uint32
   * IVLength: Uint8
   * There is a special case where the SequenceIdentifier is the Final Frame.
   */
  if (4 + ivLength + readPos > dataView.byteLength) return false

  const sequenceNumber = dataView.getUint32(readPos)
  /* Postcondition: decodeFrameBodyHeader sequenceNumber must be greater than 0. */
  needs(sequenceNumber > 0, 'Malformed sequenceNumber.')
  if (sequenceNumber === SequenceIdentifier.SEQUENCE_NUMBER_END) {
    return decodeFinalFrameBodyHeader(buffer, headerInfo, readPos)
  }

  const iv = buffer.slice((readPos += 4), (readPos += ivLength))
  return {
    sequenceNumber,
    iv,
    contentLength: frameLength,
    readPos,
    tagLength,
    isFinalFrame: false,
    contentType: ContentType.FRAMED_DATA,
  }
}

/**
 *  Exported for testing.  Used by decodeBodyHeader to compose a complete solution.
 * @param buffer Uint8Array
 * @param headerInfo HeaderInfo
 * @param readPos number
 */
export function decodeFinalFrameBodyHeader(
  buffer: Uint8Array,
  headerInfo: HeaderInfo,
  readPos: number
): FrameBodyHeader | false {
  /* Precondition: The contentType must be FRAMED_DATA to be a Final Frame. */
  needs(
    ContentType.FRAMED_DATA === headerInfo.messageHeader.contentType,
    'Unknown contentType'
  )

  const { ivLength, tagLength } = headerInfo.algorithmSuite

  /* Uint8Array is a view on top of the underlying ArrayBuffer.
   * This means that raw underlying memory stored in the ArrayBuffer
   * may be larger than the Uint8Array.  This is especially true of
   * the Node.js Buffer object.  The offset and length *must* be
   * passed to the DataView otherwise I will get unexpected results.
   */
  const dataView = new DataView(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength
  )

  /* Precondition: decodeFinalFrameBodyHeader readPos must be within the byte length of the buffer given. */
  needs(
    dataView.byteLength >= readPos && readPos >= 0,
    'readPos out of bounds.'
  )
  /* Check for early return (Postcondition): There must be enough data to decodeFinalFrameBodyHeader.
   * The format expressed here is
   * SEQUENCE_NUMBER_END: Uint32(FFFF)
   * SequenceIdentifier: Uint32
   * IVLength: Uint8
   * Reserved: Uint32
   * ContentLength: Uint32
   */
  if (4 + 4 + ivLength + 4 + readPos > dataView.byteLength) return false

  /* The precondition SEQUENCE_NUMBER_END: Uint32(FFFF) is handled above. */
  const sequenceEnd = dataView.getUint32(readPos, false) // big endian
  /* Postcondition: sequenceEnd must be SEQUENCE_NUMBER_END. */
  needs(
    sequenceEnd === SequenceIdentifier.SEQUENCE_NUMBER_END,
    'Malformed final frame: Invalid sequence number end value'
  )
  const sequenceNumber = dataView.getUint32((readPos += 4), false) // big endian
  /* Postcondition: decodeFinalFrameBodyHeader sequenceNumber must be greater than 0. */
  needs(sequenceNumber > 0, 'Malformed sequenceNumber.')
  const iv = buffer.slice((readPos += 4), (readPos += ivLength))
  const contentLength = dataView.getUint32(readPos)
  /* Postcondition: The final frame MUST NOT exceed the frameLength. */
  needs(
    headerInfo.messageHeader.frameLength >= contentLength,
    'Final frame length exceeds frame length.'
  )
  return {
    sequenceNumber,
    iv,
    contentLength,
    readPos: readPos + 4,
    tagLength,
    isFinalFrame: true,
    contentType: ContentType.FRAMED_DATA,
  }
}

/**
 * Exported for testing.  Used by decodeBodyHeader to compose a complete solution.
 * @param buffer Uint8Array
 * @param headerInfo HeaderInfo
 * @param readPos number
 */
export function decodeNonFrameBodyHeader(
  buffer: Uint8Array,
  headerInfo: HeaderInfo,
  readPos: number
): NonFrameBodyHeader | false {
  /* Precondition: The contentType must be NO_FRAMING. */
  needs(
    ContentType.NO_FRAMING === headerInfo.messageHeader.contentType,
    'Unknown contentType'
  )

  const { ivLength, tagLength } = headerInfo.algorithmSuite

  /* Uint8Array is a view on top of the underlying ArrayBuffer.
   * This means that raw underlying memory stored in the ArrayBuffer
   * may be larger than the Uint8Array.  This is especially true of
   * the Node.js Buffer object.  The offset and length *must* be
   * passed to the DataView otherwise I will get unexpected results.
   */
  const dataView = new DataView(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength
  )

  /* Precondition: decodeNonFrameBodyHeader readPos must be within the byte length of the buffer given. */
  needs(
    dataView.byteLength >= readPos && readPos >= 0,
    'readPos out of bounds.'
  )

  /* Check for early return (Postcondition): There must be enough data to decodeNonFrameBodyHeader.
   * The format expressed here is
   * IVLength: Uint8
   * ContentLength: Uint64
   */
  if (ivLength + 8 + readPos > dataView.byteLength) return false

  const iv = buffer.slice(readPos, (readPos += ivLength))
  const contentLengthBuff = buffer.slice(readPos, (readPos += 8))
  const contentLengthBN = new BN([...contentLengthBuff], 16, 'be')
  // This will throw if the number is larger than Number.MAX_SAFE_INTEGER.
  // i.e. a 53 bit number
  const contentLength = contentLengthBN.toNumber()
  /* Postcondition: Non-framed content length MUST NOT exceed AES-GCM safe limits.
   * https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md#encrypted-content-length
   */
  needs(
    Maximum.BYTES_PER_AES_GCM_NONCE > contentLength,
    'Content length out of bounds.'
  )
  return {
    sequenceNumber: 1,
    iv,
    contentLength,
    readPos,
    tagLength,
    isFinalFrame: true,
    contentType: ContentType.NO_FRAMING,
  }
}
