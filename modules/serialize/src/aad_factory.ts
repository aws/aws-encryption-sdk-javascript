import BN from 'bn.js'
import {ContentAADString, ContentType} from './identifiers'
import {BinaryData} from './types'
import {concatBuffers} from './concat_buffers'
import {uInt32BE} from './uint_util'

export function aadFactory(fromUtf8: (input: string) => Uint8Array) {

  return {
    messageAADContentString,
    messageAAD
  }

  function messageAADContentString({contentType, isFinalFrame}: {contentType: ContentType, isFinalFrame: boolean}) {
    switch (contentType) {
      case 1:
        return ContentAADString.NON_FRAMED_STRING_ID
      case 2:
        return isFinalFrame
          ? ContentAADString.FINAL_FRAME_STRING_ID
          : ContentAADString.FRAME_STRING_ID
      default:
        throw new Error('bad')
    }
  }

  function messageAAD(messageId: BinaryData, aadContentString: ContentAADString, seqNum: number, contentLength: number) {
    return concatBuffers(
      messageId,
      fromUtf8(aadContentString),
      uInt32BE(seqNum),
      new Uint8Array(new BN(contentLength).toArray('be', 8))
    )
  }
}
