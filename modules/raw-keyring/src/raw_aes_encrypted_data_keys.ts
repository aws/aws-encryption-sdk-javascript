// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* For raw AES keyrings the required wrapping information is stored in an EncryptedDataKey.
 * KeyNamespace (identifies the keyring "class"),
 * KeyName (identifies this specific keyring, like a KMS CMK ARN)
 *
 * {
 *   providerId: KeyNamespace
 *   providerInfo: utf8Encode(KeyName + TagLengthBits uInt32BE + IVLength uInt32BE + iv)
 *   encryptedDataKey: wrapped key + authTag
 * }
 *
 * The AAD (encryption context) is the same as the message.
 */

import { concatBuffers, uInt32BE } from '@aws-crypto/serialize'
import {
  AlgorithmSuite,
  EncryptedDataKey,
  needs,
} from '@aws-crypto/material-management'

export function rawAesEncryptedDataKeyFactory(
  toUtf8: (input: Uint8Array) => string,
  fromUtf8: (input: string) => Uint8Array
) {
  return { rawAesEncryptedDataKey }

  function rawAesEncryptedDataKey(
    keyNamespace: string,
    keyName: string,
    iv: Uint8Array,
    ciphertext: Uint8Array,
    authTag: Uint8Array
  ): EncryptedDataKey {
    const ivLength = iv.byteLength
    const authTagBitLength = authTag.byteLength * 8
    const encryptedDataKey = concatBuffers(ciphertext, authTag)
    const providerId = keyNamespace
    const rawInfo = concatBuffers(
      fromUtf8(keyName),
      uInt32BE(authTagBitLength),
      uInt32BE(ivLength),
      iv
    )
    const providerInfo = toUtf8(rawInfo)
    return new EncryptedDataKey({
      encryptedDataKey,
      providerId,
      providerInfo,
      rawInfo,
    })
  }
}

export function rawAesEncryptedPartsFactory(
  fromUtf8: (input: string) => Uint8Array
) {
  return { rawAesEncryptedParts }

  function rawAesEncryptedParts(
    suite: AlgorithmSuite,
    keyName: string,
    { encryptedDataKey, rawInfo }: EncryptedDataKey
  ) {
    /* Precondition: rawInfo must be a Uint8Array. */
    if (!(rawInfo instanceof Uint8Array))
      throw new Error('Malformed Encrypted Data Key.')
    // see above for format, slice off the "string part"
    rawInfo = rawInfo.slice(fromUtf8(keyName).byteLength)
    /* Uint8Array is a view on top of the underlying ArrayBuffer.
     * This means that raw underlying memory stored in the ArrayBuffer
     * may be larger than the Uint8Array.  This is especially true of
     * the Node.js Buffer object.  The offset and length *must* be
     * passed to the DataView otherwise I will get unexpected results.
     */
    const dataView = new DataView(
      rawInfo.buffer,
      rawInfo.byteOffset,
      rawInfo.byteLength
    )
    /* See above:
     * uInt32BE(authTagBitLength),uInt32BE(ivLength), iv
     */
    const tagLengthBits = dataView.getUint32(0, false) // big endian
    const ivLength = dataView.getUint32(4, false) // big endian
    /* Precondition: The ivLength must match the algorith suite specification. */
    needs(ivLength === suite.ivLength, 'Malformed providerInfo')
    /* Precondition: The tagLength must match the algorith suite specification. */
    needs(tagLengthBits === suite.tagLength, 'Malformed providerInfo')
    /* Precondition: The byteLength of rawInfo should match the encoded length. */
    needs(rawInfo.byteLength === 4 + 4 + ivLength, 'Malformed providerInfo')
    const tagLength = tagLengthBits / 8
    /* Precondition: The encryptedDataKey byteLength must match the algorith suite specification and encoded length. */
    needs(
      encryptedDataKey.byteLength === tagLength + suite.keyLengthBytes,
      'Malformed providerInfo'
    )
    const iv = rawInfo.slice(-ivLength)
    const authTag = encryptedDataKey.slice(-tagLength)
    const ciphertext = encryptedDataKey.slice(0, -tagLength)

    return { authTag, ciphertext, iv }
  }
}
