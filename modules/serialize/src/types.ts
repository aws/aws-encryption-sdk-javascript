// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  MessageFormat,
  NonCommittingAlgorithmSuiteIdentifier,
  CommittingAlgorithmSuiteIdentifier,
} from '@aws-crypto/material-management'
import { ContentType, ObjectType } from './identifiers'
import {
  IvLength,
  AlgorithmSuiteIdentifier,
  AlgorithmSuite,
  EncryptedDataKey,
  EncryptionContext,
} from '@aws-crypto/material-management'

export type BinaryData =
  | Int8Array
  | Int16Array
  | Int32Array
  | Uint8Array
  | Uint16Array
  | Uint32Array
  | Uint8ClampedArray
  | Float32Array
  | Float64Array
  | DataView
  | ArrayBuffer

export type MessageHeader = MessageHeaderV1 | MessageHeaderV2

export interface MessageHeaderV1
  extends Readonly<{
    version: MessageFormat.V1
    type: ObjectType
    suiteId: NonCommittingAlgorithmSuiteIdentifier
    messageId: Uint8Array
    encryptionContext: Readonly<EncryptionContext>
    encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
    contentType: ContentType
    headerIvLength: IvLength
    frameLength: number
  }> {}

export interface MessageHeaderV2
  extends Readonly<{
    version: MessageFormat.V2
    suiteId: CommittingAlgorithmSuiteIdentifier
    messageId: Uint8Array
    encryptionContext: Readonly<EncryptionContext>
    encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
    contentType: ContentType
    frameLength: number
    suiteData: Uint8Array
  }> {}

export interface BodyHeader {
  sequenceNumber: number
  iv: Uint8Array
  contentLength: number
  readPos: number
  tagLength: number
  isFinalFrame: boolean
  contentType: ContentType
}

export interface FrameBodyHeader extends BodyHeader {
  sequenceNumber: number
  iv: Uint8Array
  contentLength: number
  readPos: number
  tagLength: number
  isFinalFrame: boolean
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
  headerAuth: HeaderAuth
}

export interface HeaderAuth {
  headerIv: Uint8Array
  headerAuthTag: Uint8Array
  headerAuthLength: number
}

export interface AlgorithmSuiteConstructor<Suite extends AlgorithmSuite> {
  new (id: AlgorithmSuiteIdentifier): Suite
}

export interface DeserializeOptions {
  maxEncryptedDataKeys: number | false
}
