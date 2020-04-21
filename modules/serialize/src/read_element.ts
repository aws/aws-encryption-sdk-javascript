// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This public interface for reading part of the encrypted header is provided for
 * the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other
 * than the Encryption SDK for JavaScript.
 *
 * This is used to read the AAD Section and the Encrypted Data Key(s) section.
 *
 * See:
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-data-keys
 */

import { needs } from '@aws-crypto/material-management'
/**
 *
 * The encryption SDK stores elements in the form of length data.
 * e.g. 04data.  The length element is Uint16 Big Endian.
 * So knowing the number of elements of this form I can
 * advance through a buffer.  The rub comes when streaming
 * data.  The I may know the number of elements, but not
 * yet have all the data.  In this case I check the lengths and
 * return false.
 *
 * @param elementCount
 * @param buffer
 * @param readPos
 */
export function readElements(
  elementCount: number,
  fieldsPerElement: number,
  buffer: Uint8Array,
  readPos = 0
) {
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
  const elements = []

  /* Precondition: readPos must be non-negative and within the byte length of the buffer given. */
  needs(
    readPos >= 0 && dataView.byteLength >= readPos,
    'readPos out of bounds.'
  )

  /* Precondition: elementCount and fieldsPerElement must be non-negative. */
  needs(
    elementCount >= 0 && fieldsPerElement >= 0,
    'elementCount and fieldsPerElement must be positive.'
  )

  while (elementCount--) {
    const element = []
    let fieldCount = fieldsPerElement
    while (fieldCount--) {
      /* Check for early return (Postcondition): Enough data must exist to read the Uint16 length value. */
      if (readPos + 2 > dataView.byteLength) return false
      const length = dataView.getUint16(readPos, false) // big endian
      readPos += 2
      /* Check for early return (Postcondition): Enough data must exist length of the value. */
      if (readPos + length > dataView.byteLength) return false
      const fieldBinary = buffer.slice(readPos, readPos + length)
      element.push(fieldBinary)
      readPos += length
    }
    elements.push(element)
  }
  return { elements, readPos }
}
