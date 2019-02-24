import {ContentType, SerializationVersion, ObjectType} from './identifiers'
import {IvLength, AlgorithmSuiteIdentifier, AlgorithmSuite}  from '@aws-crypto/material-management'
import {EncryptedDataKey, EncryptionContext} from '@aws-crypto/material-management'

export type BinaryData = Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer

export interface MessageHeader {
  version: SerializationVersion
  type: ObjectType
  algorithmId: AlgorithmSuiteIdentifier
  messageId: BinaryData
  encryptionContext: EncryptionContext
  encryptedDataKeys: EncryptedDataKey[]
  contentType: ContentType
  headerIvLength: IvLength
  frameLength: number
}

export interface BodyHeader {
  sequenceNumber: number
  iv: Uint8Array
  contentLength: number
  readPos: number
  tagLength: number
  isFinalFrame: boolean,
  contentType: ContentType
}

export interface FrameBodyHeader extends BodyHeader {
  sequenceNumber: number
  iv: Uint8Array
  contentLength: number
  readPos: number
  tagLength: number
  isFinalFrame: boolean,
  contentType: ContentType.FRAMED_DATA
}
export interface NonFrameBodyHeader extends BodyHeader {
  sequenceNumber: 1
  iv: Uint8Array
  contentLength: number
  readPos: number
  tagLength: number
  isFinalFrame: true
  contentType: ContentType.NO_FRAMING
}

export type HeaderInfo = {
  messageHeader: MessageHeader
  headerLength: number
  rawHeader: Uint8Array
  algorithmSuite: AlgorithmSuite
  headerIv: Uint8Array
  headerAuthTag: Uint8Array
}

export interface IAlgorithm {
  new (id: AlgorithmSuiteIdentifier): AlgorithmSuite
}
