// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This public interface for serializing the AWS Encryption SDK Message Footer Format
 * is provided for the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other than the
 * Encryption SDK for JavaScript.
 *
 * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#footer-structure
 */

import { concatBuffers } from './concat_buffers'
import { uInt16BE } from './uint_util'
import { needs } from '@aws-crypto/material-management'

export function serializeSignatureInfo(signature: Uint8Array) {
  return concatBuffers(uInt16BE(signature.byteLength), signature)
}

export function deserializeSignature({
  buffer,
  byteOffset,
  byteLength,
}: Uint8Array) {
  /* Precondition: There must be information for a signature. */
  needs(byteLength && byteLength > 2, 'Invalid Signature')
  /* Uint8Array is a view on top of the underlying ArrayBuffer.
   * This means that raw underlying memory stored in the ArrayBuffer
   * may be larger than the Uint8Array.  This is especially true of
   * the Node.js Buffer object.  The offset and length *must* be
   * passed to the DataView otherwise I will get unexpected results.
   */
  const dataView = new DataView(buffer, byteOffset, byteLength)
  const signatureLength = dataView.getUint16(0, false) // big endian
  /* Precondition: The signature length must be positive. */
  needs(signatureLength > 0, 'Invalid Signature')
  /* Precondition: The data must match the serialized length. */
  needs(byteLength === signatureLength + 2, 'Invalid Signature')
  return new Uint8Array(buffer, byteOffset + 2, signatureLength)
}
