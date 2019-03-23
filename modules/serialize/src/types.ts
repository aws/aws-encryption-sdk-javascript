/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import { ContentType, SerializationVersion, ObjectType } from './identifiers' // eslint-disable-line no-unused-vars
import { IvLength, AlgorithmSuiteIdentifier, AlgorithmSuite, EncryptedDataKey, EncryptionContext } from '@aws-crypto/material-management' // eslint-disable-line no-unused-vars

export type BinaryData = Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer

export interface MessageHeader extends Readonly<{
  version: SerializationVersion
  type: ObjectType
  suiteId: AlgorithmSuiteIdentifier
  messageId: BinaryData
  encryptionContext: Readonly<EncryptionContext>
  encryptedDataKeys: ReadonlyArray<EncryptedDataKey>
  contentType: ContentType
  headerIvLength: IvLength
  frameLength: number
}> {}

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

export interface AlgorithmSuiteConstructor<Suite extends AlgorithmSuite> {
  new (id: AlgorithmSuiteIdentifier): Suite
}
