// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This public interface for constructing the additional authenticated data (AAD)
 * is provided for the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other than the
 * Encryption SDK for JavaScript.
 *
 * This AAD is used for the Body section
 * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/body-aad-reference.html
 */

import BN from 'bn.js'
import { ContentAADString, ContentType } from './identifiers'
import { BinaryData } from './types'
import { concatBuffers } from './concat_buffers'
import { uInt32BE } from './uint_util'

export function aadFactory(fromUtf8: (input: string) => Uint8Array) {
  return {
    messageAADContentString,
    messageAAD,
  }

  function messageAADContentString({
    contentType,
    isFinalFrame,
  }: {
    contentType: ContentType
    isFinalFrame: boolean
  }) {
    switch (contentType) {
      case ContentType.NO_FRAMING:
        return ContentAADString.NON_FRAMED_STRING_ID
      case ContentType.FRAMED_DATA:
        return isFinalFrame
          ? ContentAADString.FINAL_FRAME_STRING_ID
          : ContentAADString.FRAME_STRING_ID
      default:
        throw new Error('Unrecognized content type')
    }
  }

  function messageAAD(
    messageId: BinaryData,
    aadContentString: ContentAADString,
    seqNum: number,
    contentLength: number
  ) {
    return concatBuffers(
      messageId,
      fromUtf8(aadContentString),
      uInt32BE(seqNum),
      new Uint8Array(new BN(contentLength).toArray('be', 8))
    )
  }
}
