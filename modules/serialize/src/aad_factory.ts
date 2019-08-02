/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
 * This public interface for constructing the additional authenticated data (AAD)
 * is provided for the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other than the
 * Encryption SDK for JavaScript.
 *
 * This AAD is used for the Body section
 * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/body-aad-reference.html
 */

import BN from 'bn.js'
import { ContentAADString, ContentType } from './identifiers' // eslint-disable-line no-unused-vars
import { BinaryData } from './types' // eslint-disable-line no-unused-vars
import { concatBuffers } from './concat_buffers'
import { uInt32BE } from './uint_util'

export function aadFactory (fromUtf8: (input: string) => Uint8Array) {
  return {
    messageAADContentString,
    messageAAD
  }

  function messageAADContentString ({ contentType, isFinalFrame }: {contentType: ContentType, isFinalFrame: boolean}) {
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

  function messageAAD (messageId: BinaryData, aadContentString: ContentAADString, seqNum: number, contentLength: number) {
    return concatBuffers(
      messageId,
      fromUtf8(aadContentString),
      uInt32BE(seqNum),
      new Uint8Array(new BN(contentLength).toArray('be', 8))
    )
  }
}
