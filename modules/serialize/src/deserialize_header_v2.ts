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
  AlgorithmSuite,
  needs,
  CommittingAlgorithmSuiteIdentifier,
  MessageFormat,
} from '@aws-crypto/material-management'
import { MessageIdLength } from './identifiers'
import {
  HeaderInfo,
  AlgorithmSuiteConstructor,
  MessageHeaderV2,
  DeserializeOptions,
} from './types'

// To deal with Browser and Node.js I inject a function to handle utf8 encoding.
export function deserializeHeaderV2Factory<Suite extends AlgorithmSuite>({
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
  return deserializeMessageHeaderV2

  /**
   * deserializeMessageHeaderV2
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
  function deserializeMessageHeaderV2(
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

    /* Check for early return (Postcondition): Not Enough Data. Need to have at least 37 bytes of data to begin parsing.
     * The first 37 bytes of the header are fixed length.  After that
     * there are 2 variable length sections.
     */
    const fixedLengthHeaderPrefix = 1 + 2 + MessageIdLength.V2 + 2
    if (dataView.byteLength < fixedLengthHeaderPrefix) return false // not enough data

    let headerReadPos = 0
    const version = dataView.getUint8(headerReadPos)
    // Move pos Uint8 bytes
    headerReadPos += 1
    /* Precondition: version must be the required value. */
    needs(
      version === MessageFormat.V2,
      version === 65
        ? 'Malformed Header: This blob may be base64 encoded.'
        : 'Malformed Header.'
    )
    // Read second and third bytes
    const suiteId = dataView.getUint16(
      headerReadPos,
      false
    ) as CommittingAlgorithmSuiteIdentifier // big endian
    /* Precondition: suiteId must be a committing algorithm suite. */
    needs(
      CommittingAlgorithmSuiteIdentifier[suiteId],
      'Unsupported algorithm suite.'
    )
    // Move pos Uint16 bytes
    headerReadPos += 2
    const messageId = messageBuffer.slice(
      headerReadPos,
      headerReadPos + MessageIdLength.V2
    )
    // Move pos MessageIdLength.V2 bytes
    headerReadPos += MessageIdLength.V2
    const contextLength = dataView.getUint16(headerReadPos, false) // big endian
    // Move pos Uint16 bytes
    headerReadPos += 2

    /* Check for early return (Postcondition): Not Enough Data. Caller must buffer all of the context before we can parse the next section.
     * This is the first variable length section.
     */
    if (fixedLengthHeaderPrefix + contextLength > dataView.byteLength)
      return false // not enough data

    const encryptionContext = decodeEncryptionContext(
      messageBuffer.slice(
        fixedLengthHeaderPrefix,
        fixedLengthHeaderPrefix + contextLength
      )
    )
    const dataKeyInfo = deserializeEncryptedDataKeys(
      messageBuffer,
      fixedLengthHeaderPrefix + contextLength,
      deserializeOptions
    )

    /* Check for early return (Postcondition): Not Enough Data. Caller must buffer all of the encrypted data keys before we can parse the next section.
     * deserializeEncryptedDataKeys will return false if it does not have enough data.
     * This is the second variable length section.
     */
    if (!dataKeyInfo) return false // not enough data

    const { encryptedDataKeys, readPos } = dataKeyInfo

    /* I'm doing this here, after decodeEncryptionContext and deserializeEncryptedDataKeys
     * because they are the bulk of the header section.
     */
    const algorithmSuite = new SdkSuite(suiteId)
    const { tagLength, suiteDataLength, ivLength } = algorithmSuite
    /* Precondition UNTESTED: suiteId must match supported algorithm suite.
     * I'm doing this here to double up the check on suiteDataLength.
     * Ideally the types would all match up,
     * since all CommittingAlgorithmSuiteIdentifier will have `suiteDataLength`.
     * But my typescript foo is still not strong enough.
     */
    needs(
      CommittingAlgorithmSuiteIdentifier[suiteId] && suiteDataLength,
      'Unsupported algorithm suite.'
    )
    const tagLengthBytes = tagLength / 8
    const headerLength = readPos + 1 + 4 + suiteDataLength

    /* Check for early return (Postcondition): Not Enough Data. Need to have the header auth section. */
    if (headerLength + tagLengthBytes > dataView.byteLength) return false // not enough data

    // update to current position
    headerReadPos = readPos
    const contentType = dataView.getUint8(headerReadPos)
    // Move pos Uint8 bytes
    headerReadPos += 1
    const frameLength = dataView.getUint32(headerReadPos, false) // big endian
    // Move pos Uint32 bytes
    headerReadPos += 4
    const suiteData = messageBuffer.slice(
      headerReadPos,
      headerReadPos + suiteDataLength
    )
    // Move pos suiteDataLength bytes
    headerReadPos += suiteDataLength

    const rawHeader = messageBuffer.slice(0, headerLength)

    const messageHeader: MessageHeaderV2 = {
      version,
      suiteId,
      messageId,
      encryptionContext,
      encryptedDataKeys,
      contentType,
      frameLength,
      suiteData,
    }

    /* The V2 format is explicit about the IV. */
    const headerIv = new Uint8Array(ivLength)
    const headerAuthTag = messageBuffer.slice(
      headerLength,
      headerLength + tagLengthBytes
    )

    return {
      messageHeader,
      headerLength,
      rawHeader,
      algorithmSuite,
      headerAuth: {
        headerIv,
        headerAuthTag,
        headerAuthLength: headerAuthTag.byteLength,
      },
    }
  }
}
