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

import { EncryptionContext, needs } from '@aws-crypto/material-management'
import { readElements } from './read_element'

// To deal with Browser and Node.js I inject a function to handle utf8 encoding.
export function decodeEncryptionContextFactory(
  toUtf8: (input: Uint8Array) => string
) {
  return decodeEncryptionContext

  /**
   * Exported for testing.  Used by deserializeMessageHeader to compose a complete solution.
   * @param encodedEncryptionContext Uint8Array
   */
  function decodeEncryptionContext(
    encodedEncryptionContext: Uint8Array
  ): Readonly<EncryptionContext> {
    const encryptionContext: EncryptionContext = Object.create(null)
    /* Check for early return (Postcondition): The case of 0 length is defined as an empty object. */
    if (!encodedEncryptionContext.byteLength) {
      return Object.freeze(encryptionContext)
    }
    /* Uint8Array is a view on top of the underlying ArrayBuffer.
     * This means that raw underlying memory stored in the ArrayBuffer
     * may be larger than the Uint8Array.  This is especially true of
     * the Node.js Buffer object.  The offset and length *must* be
     * passed to the DataView otherwise I will get unexpected results.
     */
    const dataView = new DataView(
      encodedEncryptionContext.buffer,
      encodedEncryptionContext.byteOffset,
      encodedEncryptionContext.byteLength
    )
    const pairsCount = dataView.getUint16(0, false) // big endian
    const elementInfo = readElements(pairsCount, 2, encodedEncryptionContext, 2)
    /* Postcondition: Since the encryption context has a length, it must have pairs.
     * Unlike the encrypted data key section, the encryption context has a length
     * element.  This means I should always pass the entire section.
     */
    if (!elementInfo) throw new Error('context parse error')
    const { elements, readPos } = elementInfo

    /* Postcondition: The byte length of the encodedEncryptionContext must match the readPos. */
    needs(
      encodedEncryptionContext.byteLength === readPos,
      'Overflow, too much data.'
    )

    for (let count = 0; count < pairsCount; count++) {
      const [key, value] = elements[count].map(toUtf8)
      /* Postcondition: The number of keys in the encryptionContext must match the pairsCount.
       * If the same Key value is serialized...
       */
      needs(
        encryptionContext[key] === undefined,
        'Duplicate encryption context key value.'
      )
      encryptionContext[key] = value
    }
    Object.freeze(encryptionContext)
    return encryptionContext
  }
}
