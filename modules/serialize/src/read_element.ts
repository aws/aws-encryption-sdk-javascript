/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
export function readElements (
  elementCount: number,
  buffer: Uint8Array,
  readPos: number = 0
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

  /* Precondition: readPos must be within the byte length of the buffer given. */
  needs(dataView.byteLength >= readPos && readPos >= 0, 'readPos out of bounds.')

  /* Precondition: elementCount must not be negative. */
  needs(elementCount >= 0, 'elementCount must be positive.')

  while (elementCount--) {
    /* Check for early return (Postcondition): Enough data must exist to read the Uint16 length value. */
    if (readPos + 2 > dataView.byteLength) return false
    const length = dataView.getUint16(readPos, false)
    readPos += 2
    /* Check for early return (Postcondition): Enough data must exist length of the value. */
    if (readPos + length > dataView.byteLength) return false
    const elementBinary = buffer.slice(readPos, readPos + length)
    elements.push(elementBinary)
    readPos += length
  }
  return { elements, readPos }
}
