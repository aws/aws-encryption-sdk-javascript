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
 * This public interface for parsing the AWS Encryption SDK Message Header Format
 * is provided for the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other than the
 * Encryption SDK for JavaScript.
 *
 * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-structure
 */

import { IvLength, AlgorithmSuiteIdentifier, EncryptedDataKey, EncryptionContext, needs } from '@aws-crypto/material-management' // eslint-disable-line no-unused-vars
import { HeaderInfo, IAlgorithm } from './types' // eslint-disable-line no-unused-vars
import { readElements } from './read_element'

// To deal with Browser and Node.js I inject a function to handle utf8 encoding.
export function deserializeFactory (toUtf8: (input: Uint8Array) => string, SdkAlgorithm: IAlgorithm) {
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

    /* Precondition: Not Enough Data. Need to have at least 22 bytes of data to begin parsing.
     * The first 22 bytes of the header are fixed length.  After that
     * there are 2 variable length sections.
     */
    if (dataView.byteLength < 22) return false // not enough data

    const version = dataView.getUint8(0)
    const type = dataView.getUint8(1)

    /* Precondition: algorithmId must match supported algorithm suite */
    needs(AlgorithmSuiteIdentifier[dataView.getUint16(2)], 'Unsupported algorithm suite.')
    const algorithmId = <AlgorithmSuiteIdentifier>dataView.getUint16(2)
    const messageId = messageBuffer.slice(4, 20)
    const contextLength = dataView.getUint16(20)

    /* Precondition: Not Enough Data. Need to have all of the context in bytes before we can parse the next section.
     * This is the first variable length section.
     */
    if (22 + contextLength > dataView.byteLength) return false // not enough data

    const contextBuffer = messageBuffer.slice(22, 22 + contextLength)
    const encryptionContext = decodeEncryptionContext(contextBuffer)
    const dataKeyInfo = deserializeEncryptedDataKeys(messageBuffer, 22 + contextLength)

    /* Precondition: Not Enough Data. deserializeEncryptedDataKeys will return false if it does not have enough data.
     * This is the second variable length section.
     */
    if (!dataKeyInfo) return false // not enough data

    const { encryptedDataKeys, readPos } = dataKeyInfo
    const headerLength = readPos + 1 + 4 + 1 + 4

    /* Precondition: Not Enough Data. Need to have the remaining fixed length data to parse. */
    if (headerLength > dataView.byteLength) return false // not enough data

    const contentType = dataView.getUint8(readPos)
    // reserved data 4 bytes
    const headerIvLength = <IvLength>dataView.getUint8(readPos + 1 + 4)
    const frameLength = dataView.getUint32(readPos + 1 + 4 + 1)
    const rawHeader = messageBuffer.slice(0, headerLength)

    const messageHeader = {
      version,
      type,
      algorithmId,
      messageId,
      encryptionContext,
      encryptedDataKeys,
      contentType,
      headerIvLength,
      frameLength
    }

    const algorithmSuite = new SdkAlgorithm(messageHeader.algorithmId)
    const { ivLength, tagLength } = algorithmSuite
    const tagLengthBytes = tagLength / 8

    /* Precondition: Not Enough Data. Need to have the Header Auth section.  This is derived from the algorithm suite specification. */
    if (headerLength + ivLength + tagLengthBytes > dataView.byteLength) return false // not enough data

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
  function deserializeEncryptedDataKeys (buffer: Uint8Array, startPos: number) {
    /* Precondition: startPos must be within the byte length of the buffer given. */
    if (startPos < 0 || startPos > buffer.byteLength) throw new Error('')

    /* Precondition: Need to have at least Uint16 (2) bytes of data. */
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
    const encryptedDataKeysCount = dataView.getUint16(startPos)

    /* Precondition: There must be at least 1 EncryptedDataKey element. */
    if (encryptedDataKeysCount === 0) throw new Error('')

    const elementInfo = readElements(encryptedDataKeysCount * 3, buffer, startPos + 2)
    /* Precondition: readElement will return false if there is not enough data.
     * I can only continue if I have at least the entire EDK section.
     */
    if (!elementInfo) return false
    const { elements, readPos } = elementInfo

    let keyCount = encryptedDataKeysCount
    const encryptedDataKeys = []
    while (keyCount--) {
      const [providerId, providerInfo] = elements.splice(0, 2).map(toUtf8)
      const [encryptedDataKey] = elements.splice(0, 1)
      const edk = new EncryptedDataKey({ providerInfo, providerId, encryptedDataKey })
      encryptedDataKeys.push(edk)
    }
    return { encryptedDataKeys, readPos }
  }

  /**
   * Exported for testing.  Used by deserializeMessageHeader to compose a complete solution.
   * @param encodedEncryptionContext Uint8Array
   */
  function decodeEncryptionContext (encodedEncryptionContext: Uint8Array) {
    const encryptionContext: EncryptionContext = {}
    /* Precondition: The case of 0 length is defined as an empty object. */
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
    const pairsCount = dataView.getUint16(0)
    const elementInfo = readElements(pairsCount * 2, encodedEncryptionContext, 2)
    /* Postcondition: Since the encryption context has a length, it must have pairs.
     * Unlike the encrypted data key section, the encryption context has a length
     * element.  This means I should always pass the entire section.
     */

    if (!elementInfo) throw new Error('context parse error')
    const { elements, readPos } = elementInfo

    /* Postcondition: The byte length of the encodedEncryptionContext must match the readPos. */
    if (encodedEncryptionContext.byteLength !== readPos) throw new Error('')

    let count = pairsCount
    while (count--) {
      const [key, value] = elements.splice(0, 2).map(toUtf8)
      encryptionContext[key] = value
    }
    /* Postcondition: The number of keys in the encryptionContext must match the pairsCount.
     * If the same Key value is serialized...
     */
    if (Object.keys(encryptionContext).length !== pairsCount) throw new Error('')
    return encryptionContext
  }
}
