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

import { AlgorithmSuite, needs } from '@aws-crypto/material-management'
import {
  HeaderInfo,
  AlgorithmSuiteConstructor,
  DeserializeOptions,
} from './types'
import { decodeEncryptionContextFactory } from './decode_encryption_context'
import { deserializeEncryptedDataKeysFactory } from './deserialize_encrypted_data_keys'
import { deserializeHeaderV1Factory } from './deserialize_header_v1'
import { deserializeHeaderV2Factory } from './deserialize_header_v2'

// To deal with Browser and Node.js I inject a function to handle utf8 encoding.
export function deserializeFactory<Suite extends AlgorithmSuite>(
  toUtf8: (input: Uint8Array) => string,
  SdkSuite: AlgorithmSuiteConstructor<Suite>
) {
  const decodeEncryptionContext = decodeEncryptionContextFactory(toUtf8)
  const deserializeEncryptedDataKeys =
    deserializeEncryptedDataKeysFactory(toUtf8)

  const deserializeHeaderV1 = deserializeHeaderV1Factory({
    decodeEncryptionContext,
    deserializeEncryptedDataKeys,
    SdkSuite,
  })

  const deserializeHeaderV2 = deserializeHeaderV2Factory({
    decodeEncryptionContext,
    deserializeEncryptedDataKeys,
    SdkSuite,
  })

  /* The first byte holds the message format version.
   * So this maps a version to a deserializer.
   */
  const deserializeMap = new Map([
    /* I have no idea why someone
     * is going to call me with an empty buffer.
     * But since that is clearly not enough data
     * the right thing seems to be to ask for more data.
     * An unknown version can't be invalid.
     */
    [undefined, (_: Uint8Array): false | HeaderInfo => false],
    [1, deserializeHeaderV1],
    [2, deserializeHeaderV2],
  ])

  return {
    deserializeMessageHeader,
    deserializeEncryptedDataKeys,
    decodeEncryptionContext,
  }

  function deserializeMessageHeader(
    messageBuffer: Uint8Array,
    deserializeOptions: DeserializeOptions = { maxEncryptedDataKeys: false }
  ): HeaderInfo | false {
    const messageFormatVersion = messageBuffer[0]
    const deserializer = deserializeMap.get(messageFormatVersion)
    /* Precondition: A valid deserializer must exist. */
    needs(deserializer, 'Not a supported message format version.')

    return deserializer(messageBuffer, deserializeOptions)
  }
}
