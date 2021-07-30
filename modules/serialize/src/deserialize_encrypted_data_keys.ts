// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This public interface for parsing the AWS Encryption SDK Message Header Format
 * is provided for the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other than the
 * Encryption SDK for JavaScript.
 *
 * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-structure
 */

import { EncryptedDataKey, needs } from '@aws-crypto/material-management'
import { DeserializeOptions } from './types'
import { readElements } from './read_element'

// To deal with Browser and Node.js I inject a function to handle utf8 encoding.
export function deserializeEncryptedDataKeysFactory(
  toUtf8: (input: Uint8Array) => string
) {
  return deserializeEncryptedDataKeys

  /**
   * Exported for testing.  Used by deserializeMessageHeader to compose a complete solution.
   * @param buffer Uint8Array
   * @param startPos number
   * @param deserializeOptions DeserializeOptions
   */
  function deserializeEncryptedDataKeys(
    buffer: Uint8Array,
    startPos: number,
    { maxEncryptedDataKeys }: DeserializeOptions = {
      maxEncryptedDataKeys: false,
    }
  ):
    | { encryptedDataKeys: ReadonlyArray<EncryptedDataKey>; readPos: number }
    | false {
    /* Precondition: startPos must be within the byte length of the buffer given. */
    needs(
      buffer.byteLength >= startPos && startPos >= 0,
      'startPos out of bounds.'
    )

    /* Precondition: deserializeEncryptedDataKeys needs a valid maxEncryptedDataKeys. */
    needs(
      maxEncryptedDataKeys === false || maxEncryptedDataKeys >= 1,
      'Invalid maxEncryptedDataKeys value.'
    )

    /* Check for early return (Postcondition): Need to have at least Uint16 (2) bytes of data. */
    if (startPos + 2 > buffer.byteLength) return false

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
    const encryptedDataKeysCount = dataView.getUint16(startPos, false) // big endian

    /* Precondition: There must be at least 1 EncryptedDataKey element. */
    needs(encryptedDataKeysCount, 'No EncryptedDataKey found.')

    /* Precondition: encryptedDataKeysCount must not exceed maxEncryptedDataKeys. */
    needs(
      maxEncryptedDataKeys === false ||
        encryptedDataKeysCount <= maxEncryptedDataKeys,
      'maxEncryptedDataKeys exceeded.'
    )

    const elementInfo = readElements(
      encryptedDataKeysCount,
      3,
      buffer,
      startPos + 2
    )
    /* Check for early return (Postcondition): readElement will return false if there is not enough data.
     * I can only continue if I have at least the entire EDK section.
     */
    if (!elementInfo) return false
    const { elements, readPos } = elementInfo

    const encryptedDataKeys = elements.map(
      ([rawId, rawInfo, encryptedDataKey]) => {
        const providerId = toUtf8(rawId)
        const providerInfo = toUtf8(rawInfo)
        return new EncryptedDataKey({
          providerInfo,
          providerId,
          encryptedDataKey,
          rawInfo,
        })
      }
    )
    Object.freeze(encryptedDataKeys)
    return { encryptedDataKeys, readPos }
  }
}
