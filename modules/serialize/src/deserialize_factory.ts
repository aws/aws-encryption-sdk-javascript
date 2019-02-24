// import BN from 'bn.js' // for Non-Framed ContentLength...
import {IvLength, AlgorithmSuiteIdentifier, EncryptedDataKey, EncryptionContext} from '@aws-crypto/material-management'
import {HeaderInfo, IAlgorithm} from './types'
import {readElements} from './read_element'

export function deserializeFactory(toUtf8: (input: Uint8Array) => string, SdkAlgorithm: IAlgorithm) {

  return {
    deserializeMessageHeader,
    deserializeEncryptedDataKeys,
    decodeEncryptionContext
  }

  function deserializeMessageHeader(messageBuffer: Uint8Array): HeaderInfo|false {
    const dataView = new DataView(messageBuffer.buffer)

    if (22 > dataView.byteLength) return false // not enough data

    const version = dataView.getUint8(0)
    const type = dataView.getUint8(1)
    const algorithmId = <AlgorithmSuiteIdentifier>dataView.getUint16(2)
    const messageId = messageBuffer.slice(4, 20)
    const contextLength = dataView.getUint16(20)

    if (22 + contextLength > dataView.byteLength) return false // not enough data

    const contextBuffer = messageBuffer.slice(22, 22 + contextLength)
    const encryptionContext = decodeEncryptionContext(contextBuffer)
    const dataKeyInfo = deserializeEncryptedDataKeys(messageBuffer, 22 + contextLength)

    if (!dataKeyInfo) return false // not enough data

    const {encryptedDataKeys, readPos} = dataKeyInfo
    const headerLength = readPos + 1 + 4 + 1 + 4

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
    const {ivLength, tagLength} = algorithmSuite
    const tagLengthBytes = tagLength/8

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

  function deserializeEncryptedDataKeys(buffer: Uint8Array, startPos: number) {
    if (startPos + 2 > buffer.byteLength) return false
    const dataView = new DataView(buffer.buffer)
    const encryptedDataKeysCount = dataView.getUint16(startPos)
    const elementInfo = readElements(encryptedDataKeysCount * 3, buffer, startPos + 2)
    if (!elementInfo) return false
    const {elements, readPos} = elementInfo

    let keyCount = encryptedDataKeysCount
    const encryptedDataKeys = []
    while (keyCount--) {
      const [providerId, providerInfo] = elements.splice(0, 2).map(toUtf8)
      const [encryptedDataKey] = elements.splice(0, 1)
      const edk = new EncryptedDataKey({providerInfo, providerId, encryptedDataKey})
      encryptedDataKeys.push(edk)
    }
    encryptedDataKeys.length === encryptedDataKeysCount // assert
    return {encryptedDataKeys, readPos}
  }

  function decodeEncryptionContext(encodedEncryptionContext: Uint8Array) {
    const encryptionContext: EncryptionContext = {}
    if (!encodedEncryptionContext.byteLength) {
      return encryptionContext
    }
    const dataView = new DataView(encodedEncryptionContext.buffer)
    const pairsCount = dataView.getUint16(0)
    const elementInfo = readElements(pairsCount * 2, encodedEncryptionContext, 2)
    if (!elementInfo) throw new Error('context parse error')
    const {elements, readPos} = elementInfo

    let count = pairsCount
    while (count--) {
      const [key, value] = elements.splice(0, 2).map(toUtf8)
      encryptionContext[key] = value
    }
    Object.keys(encryptionContext).length === pairsCount // assert count good
    encodedEncryptionContext.byteLength === readPos // assert length good
    return encryptionContext
  }
}
