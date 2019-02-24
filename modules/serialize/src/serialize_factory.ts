import {concatBuffers} from './concat_buffers'
import {IvLength, EncryptionContext, IEncryptedDataKey} from '@aws-crypto/material-management'
import {SequenceIdentifier} from './identifiers'
import {uInt16BE, uInt8, uInt32BE} from './uint_util'
import {MessageHeader} from './types'

export function serializeFactory(fromUtf8: (input: any) => Uint8Array) {

  return {
    frameIv,
    nonFramedBodyIv,
    headerAuthIv,
    frameHeader,
    finalFrameHeader,
    encodeEncryptionContext,
    serializeEncryptionContext,
    serializeEncryptedDataKeys,
    serializeMessageHeader,
  }

  function frameIv(ivLength: IvLength, sequenceNumber: number) {
    if (sequenceNumber < 1) {
      throw new Error('bad')
    }

    const buff = new Uint8Array(ivLength)
    const view = new DataView(buff.buffer)
    view.setUint32(ivLength - 4, sequenceNumber, false) // big-endian
    return buff
  }

  function nonFramedBodyIv(ivLength: IvLength) {
    return frameIv(ivLength, 1)
  }
  
  function headerAuthIv(ivLength: IvLength) {
    return new Uint8Array(ivLength)
  }

  function frameHeader(sequenceNumber:number, iv: Uint8Array) {
    return concatBuffers(uInt32BE(sequenceNumber), iv)
  }

  function finalFrameHeader(sequenceNumber: number, iv: Uint8Array, contentLength: number) {
    return concatBuffers(
      uInt32BE(SequenceIdentifier.SEQUENCE_NUMBER_END), // Final Frame identifier
      uInt32BE(sequenceNumber),
      iv,
      uInt32BE(contentLength))
  }

  function encodeEncryptionContext(encryptionContext: EncryptionContext) {
    return Object
      .entries(encryptionContext)
      .map(entries => entries.map(fromUtf8))
      .map(([key, value]) => concatBuffers(uInt16BE(key.byteLength), key, uInt16BE(value.byteLength), value))
  }

  function serializeEncryptionContext(encodedEncryptionContext: Uint8Array[]) {
    // If there is no context then the length of the _whole_ serialized portion is 0
    if (!encodedEncryptionContext.length) return new Uint8Array(uInt16BE(0))

    const aadData = concatBuffers(uInt16BE(encodedEncryptionContext.length), ...encodedEncryptionContext)
    const aadLength = uInt16BE(aadData.byteLength)
    return concatBuffers(aadLength, aadData)
  }

  function serializeEncryptedDataKeys(encryptedDataKeys: IEncryptedDataKey[]) {
    const encryptedKeyInfo = encryptedDataKeys
      .map(({providerId, providerInfo, encryptedDataKey}) => {
        const [providerIdBytes, keyInfoBytes] = [providerId, providerInfo].map(fromUtf8)
        return concatBuffers(
          uInt16BE(providerIdBytes.byteLength), providerIdBytes,
          uInt16BE(keyInfoBytes.byteLength), keyInfoBytes,
          uInt16BE(encryptedDataKey.byteLength), encryptedDataKey,
        )
      })

    return concatBuffers(
      uInt16BE(encryptedDataKeys.length),
      ...encryptedKeyInfo
    )
  }

  function serializeMessageHeader(messageHeader: MessageHeader) {
    return concatBuffers(
      uInt8(messageHeader.version),
      uInt8(messageHeader.type),
      uInt16BE(messageHeader.algorithmId),
      messageHeader.messageId,
      serializeEncryptionContext(encodeEncryptionContext(messageHeader.encryptionContext)),
      serializeEncryptedDataKeys(messageHeader.encryptedDataKeys),
      new Uint8Array([messageHeader.contentType]),
      new Uint8Array([0, 0, 0, 0]),
      uInt8(messageHeader.headerIvLength),
      uInt32BE(messageHeader.frameLength)
    )
  }
}
