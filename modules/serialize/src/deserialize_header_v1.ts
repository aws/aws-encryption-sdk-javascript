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
  EncryptionContext,
  EncryptedDataKey,
  IvLength,
  AlgorithmSuite,
  needs,
  NonCommittingAlgorithmSuiteIdentifier,
  MessageFormat,
} from '@aws-crypto/material-management'
import {
  HeaderInfo,
  AlgorithmSuiteConstructor,
  MessageHeader,
  DeserializeOptions,
} from './types'

// To deal with Browser and Node.js I inject a function to handle utf8 encoding.
export function deserializeHeaderV1Factory<Suite extends AlgorithmSuite>({
  decodeEncryptionContext,
  deserializeEncryptedDataKeys,
  SdkSuite,
}: {
  decodeEncryptionContext: (
    encodedEncryptionContext: Uint8Array
  ) => EncryptionContext
  deserializeEncryptedDataKeys: (
    buffer: Uint8Array,
    startPos: number,
    deserializeOptions?: DeserializeOptions
  ) =>
    | false
    | {
        encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
        readPos: number
      }
  SdkSuite: AlgorithmSuiteConstructor<Suite>
}) {
  return deserializeMessageHeaderV1

  /**
   * deserializeMessageHeaderV1
   *
   * I need to be able to parse the MessageHeader, but since the data may be streamed
   * I may not have all the data yet.  The caller is expected to maintain and append
   * to the buffer and call this function with the same readPos until the function
   * returns a HeaderInfo.
   *
   * @param messageBuffer
   * @param deserializeOptions
   * @returns HeaderInfo|undefined
   */
  function deserializeMessageHeaderV1(
    messageBuffer: Uint8Array,
    deserializeOptions: DeserializeOptions = { maxEncryptedDataKeys: false }
  ): HeaderInfo | false {
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
    needs(
      version === MessageFormat.V1 && type === 128,
      version === 65 && type === 89
        ? 'Malformed Header: This blob may be base64 encoded.'
        : 'Malformed Header.'
    )

    const suiteId = dataView.getUint16(
      2,
      false
    ) as NonCommittingAlgorithmSuiteIdentifier // big endian
    /* Precondition: suiteId must be a non-committing algorithm suite. */
    needs(
      NonCommittingAlgorithmSuiteIdentifier[suiteId],
      'Unsupported algorithm suite.'
    )
    const messageId = messageBuffer.slice(4, 20)
    const contextLength = dataView.getUint16(20, false) // big endian

    /* Check for early return (Postcondition): Not Enough Data. Need to have all of the context in bytes before we can parse the next section.
     * This is the first variable length section.
     */
    if (22 + contextLength > dataView.byteLength) return false // not enough data

    const encryptionContext = decodeEncryptionContext(
      messageBuffer.slice(22, 22 + contextLength)
    )
    const dataKeyInfo = deserializeEncryptedDataKeys(
      messageBuffer,
      22 + contextLength,
      deserializeOptions
    )

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
    if (headerLength + ivLength + tagLengthBytes > dataView.byteLength)
      return false // not enough data

    const contentType = dataView.getUint8(readPos)
    const reservedBytes = dataView.getUint32(readPos + 1, false) // big endian
    /* Postcondition: reservedBytes are defined as 0,0,0,0
     * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-reserved
     */
    needs(reservedBytes === 0, 'Malformed Header')
    const headerIvLength = dataView.getUint8(readPos + 1 + 4) as IvLength
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
      frameLength,
    }

    const headerIv = messageBuffer.slice(headerLength, headerLength + ivLength)
    const headerAuthTag = messageBuffer.slice(
      headerLength + ivLength,
      headerLength + ivLength + tagLengthBytes
    )

    return {
      messageHeader,
      headerLength,
      rawHeader,
      algorithmSuite,
      headerAuth: {
        headerIv,
        headerAuthTag,
        headerAuthLength: headerIv.byteLength + headerAuthTag.byteLength,
      },
    }
  }
}
