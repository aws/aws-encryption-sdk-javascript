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

import {
  IvLength, // eslint-disable-line no-unused-vars
  AlgorithmSuiteIdentifier,
  AlgorithmSuite, // eslint-disable-line no-unused-vars
  EncryptedDataKey,
  EncryptionContext, // eslint-disable-line no-unused-vars
  needs
} from '@aws-crypto/material-management'
import { HeaderInfo, AlgorithmSuiteConstructor, MessageHeader } from './types' // eslint-disable-line no-unused-vars
import { readElements } from './read_element'

// To deal with Browser and Node.js I inject a function to handle utf8 encoding.
export function deserializeFactory<Suite extends AlgorithmSuite> (
  toUtf8: (input: Uint8Array) => string,
  SdkSuite: AlgorithmSuiteConstructor<Suite>
) {
  return {
    deserializeMessageHeader,
    deserializeEncryptedDataKeys,
    decodeEncryptionContext
  }

  /**
   * deserializeMessageHeader
   *
   * I need to be able to parse the MessageHeader, but since the data may be streamed
   * I may not have all the data yet.  The caller is expected to maintain and append
   * to the buffer and call this function with the same readPos until the function
   * returns a HeaderInfo.
   *
   * @param messageBuffer
   * @returns HeaderInfo|undefined
   */
  function deserializeMessageHeader (messageBuffer: Uint8Array): HeaderInfo|false {
    /* Uint8Array is a view on top of the underlying ArrayBuffer.
     * This means that raw underlying memory stored in the ArrayBuffer
     * may be larger than the Uint8Array.  This is especially true of
     * the Node.js Buffer object.  The offset and length *must* be
     * passed to the DataView otherwise I will get unexpected results.
     */
    const dataView = new DataView(
      messageBuffer.buffer,
      messageBuffer.byteOffset,
      messageBuffer.byteLength
    )

    /* Check for early return (Postcondition): Not Enough Data. Need to have at least 22 bytes of data to begin parsing.
     * The first 22 bytes of the header are fixed length.  After that
     * there are 2 variable length sections.
     */
    if (dataView.byteLength < 22) return false // not enough data

    const version = dataView.getUint8(0)
    const type = dataView.getUint8(1)
    /* Precondition: version and type must be the required values. */
    needs(version === 1 && type === 128,
      version === 65 && type === 89 ? 'Malformed Header: This blob may be base64 encoded.' : 'Malformed Header.')

    const suiteId = <AlgorithmSuiteIdentifier>dataView.getUint16(2, false) // big endian
    /* Precondition: suiteId must match supported algorithm suite */
    needs(AlgorithmSuiteIdentifier[suiteId], 'Unsupported algorithm suite.')
    const messageId = messageBuffer.slice(4, 20)
    const contextLength = dataView.getUint16(20, false) // big endian

    /* Check for early return (Postcondition): Not Enough Data. Need to have all of the context in bytes before we can parse the next section.
     * This is the first variable length section.
     */
    if (22 + contextLength > dataView.byteLength) return false // not enough data

    const encryptionContext = decodeEncryptionContext(messageBuffer.slice(22, 22 + contextLength))
    const dataKeyInfo = deserializeEncryptedDataKeys(messageBuffer, 22 + contextLength)

    /* Check for early return (Postcondition): Not Enough Data. deserializeEncryptedDataKeys will return false if it does not have enough data.
     * This is the second variable length section.
     */
    if (!dataKeyInfo) return false // not enough data

    const { encryptedDataKeys, readPos } = dataKeyInfo

    /* I'm doing this here, after decodeEncryptionContext and deserializeEncryptedDataKeys
     * because they are the bulk of the header section.
     */
    const algorithmSuite = new SdkSuite(suiteId)
    const { ivLength, tagLength } = algorithmSuite
    const tagLengthBytes = tagLength / 8
    const headerLength = readPos + 1 + 4 + 1 + 4

    /* Check for early return (Postcondition): Not Enough Data. Need to have the remaining fixed length data to parse. */
    if (headerLength + ivLength + tagLengthBytes > dataView.byteLength) return false // not enough data

    const contentType = dataView.getUint8(readPos)
    const reservedBytes = dataView.getUint32(readPos + 1, false) // big endian
    /* Postcondition: reservedBytes are defined as 0,0,0,0
     * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-reserved
     */
    needs(reservedBytes === 0, 'Malformed Header')
    const headerIvLength = <IvLength>dataView.getUint8(readPos + 1 + 4)
    /* Postcondition: The headerIvLength must match the algorithm suite specification. */
    needs(headerIvLength === ivLength, 'Malformed Header')
    const frameLength = dataView.getUint32(readPos + 1 + 4 + 1, false) // big endian
    const rawHeader = messageBuffer.slice(0, headerLength)

    const messageHeader: MessageHeader = {
      version,
      type,
      suiteId,
      messageId,
      encryptionContext,
      encryptedDataKeys,
      contentType,
      headerIvLength,
      frameLength
    }

    const headerIv = messageBuffer.slice(headerLength, headerLength + ivLength)
    const headerAuthTag = messageBuffer.slice(headerLength + ivLength, headerLength + ivLength + tagLengthBytes)

    return {
      messageHeader,
      headerLength,
      rawHeader,
      algorithmSuite,
      headerIv,
      headerAuthTag
    }
  }

  /**
   * Exported for testing.  Used by deserializeMessageHeader to compose a complete solution.
   * @param buffer Uint8Array
   * @param startPos number
   */
  function deserializeEncryptedDataKeys (buffer: Uint8Array, startPos: number): {encryptedDataKeys: ReadonlyArray<EncryptedDataKey>, readPos: number}|false {
    /* Precondition: startPos must be within the byte length of the buffer given. */
    needs(buffer.byteLength >= startPos && startPos >= 0, 'startPos out of bounds.')

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

    const elementInfo = readElements(encryptedDataKeysCount, 3, buffer, startPos + 2)
    /* Check for early return (Postcondition): readElement will return false if there is not enough data.
     * I can only continue if I have at least the entire EDK section.
     */
    if (!elementInfo) return false
    const { elements, readPos } = elementInfo

    const encryptedDataKeys = elements.map(
      ([rawId, rawInfo, encryptedDataKey], _) => {
        const providerId = toUtf8(rawId)
        const providerInfo = toUtf8(rawInfo)
        return new EncryptedDataKey({ providerInfo, providerId, encryptedDataKey, rawInfo })
      }
    )
    Object.freeze(encryptedDataKeys)
    return { encryptedDataKeys, readPos }
  }

  /**
   * Exported for testing.  Used by deserializeMessageHeader to compose a complete solution.
   * @param encodedEncryptionContext Uint8Array
   */
  function decodeEncryptionContext (encodedEncryptionContext: Uint8Array) {
    const encryptionContext: EncryptionContext = Object.create(null)
    /* Check for early return (Postcondition): The case of 0 length is defined as an empty object. */
    if (!encodedEncryptionContext.byteLength) {
      return encryptionContext
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
    needs(encodedEncryptionContext.byteLength === readPos, 'Overflow, too much data.')

    for (let count = 0; count < pairsCount; count++) {
      const [key, value] = elements[count].map(toUtf8)
      /* Postcondition: The number of keys in the encryptionContext must match the pairsCount.
       * If the same Key value is serialized...
       */
      needs(encryptionContext[key] === undefined, 'Duplicate encryption context key value.')
      encryptionContext[key] = value
    }
    Object.freeze(encryptionContext)
    return encryptionContext
  }
}
