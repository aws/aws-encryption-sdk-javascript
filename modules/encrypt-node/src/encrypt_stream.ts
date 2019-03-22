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

import {
  NodeCryptographicMaterialsManager, NodeAlgorithmSuite, AlgorithmSuiteIdentifier, // eslint-disable-line no-unused-vars
  NodeKeyring, NodeEncryptionMaterial, getEncryptHelper, EncryptionContext // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import { getFramedEncryptStream } from './framed_encrypt_stream'
import { SignatureStream } from './signature_stream'
import Duplexify from 'duplexify'
import { randomBytes } from 'crypto'
import {
  MessageHeader, // eslint-disable-line no-unused-vars
  serializeFactory, kdfInfo, ContentType, SerializationVersion, ObjectType
} from '@aws-crypto/serialize'

// @ts-ignore
import { pipeline } from 'readable-stream'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const { serializeMessageHeader, headerAuthIv } = serializeFactory(fromUtf8)

export interface EncryptStreamInput {
  suiteId?: AlgorithmSuiteIdentifier
  context?: EncryptionContext
  frameLength?: number
  plaintextLength?: number
}

/**
 * Takes a NodeCryptographicMaterialsManager or a NodeKeyring that will
 * be wrapped in a NodeCryptographicMaterialsManager and returns a stream.
 * 
 * @param cmm NodeCryptographicMaterialsManager|NodeKeyring
 * @param op EncryptStreamInput
 */
export function encryptStream (
  cmm: NodeCryptographicMaterialsManager|NodeKeyring,
  op: EncryptStreamInput = {}
) {
  const { suiteId, context, frameLength = 10 } = op

  /* If the cmm is not a MaterialsManager, wrap in one.
   * I am expecting the NodeCryptographicMaterialsManager to
   * handle non-keyring parameters.
   */
  cmm = cmm instanceof NodeCryptographicMaterialsManager
    ? cmm
    : new NodeCryptographicMaterialsManager(cmm)

  const suite = suiteId && new NodeAlgorithmSuite(suiteId)

  const wrappingStream = new Duplexify()

  cmm.getEncryptionMaterials({ suite, encryptionContext: context, frameLength })
    .then(async ({ material, context }) => {
      const { dispose, getSigner } = getEncryptHelper(material)

      const { getCipher, messageHeader, rawHeader } = getEncryptionInfo(material, frameLength, context)

      wrappingStream.emit('MessageHeader', messageHeader)

      const encryptStream = getFramedEncryptStream(getCipher, messageHeader, dispose)
      const signatureStream = new SignatureStream(getSigner)

      pipeline(encryptStream, signatureStream)

      wrappingStream.setReadable(signatureStream)
      // Flush the rawHeader through the signatureStream
      rawHeader.forEach(buff => signatureStream.push(buff))

      // @ts-ignore until readable-stream exports v3 types...
      wrappingStream.setWritable(encryptStream)
    })
    .catch(err => wrappingStream.emit('error', err))

  return wrappingStream
}

export function getEncryptionInfo (material : NodeEncryptionMaterial, frameLength: number, context: EncryptionContext) {
  const { kdfGetCipher } = getEncryptHelper(material)

  const messageId = randomBytes(16)
  const { id, ivLength } = material.suite
  const messageHeader: MessageHeader = Object.freeze({
    version: SerializationVersion.V1,
    type: ObjectType.CUSTOMER_AE_DATA,
    algorithmId: id,
    messageId,
    encryptionContext: context,
    encryptedDataKeys: material.encryptedDataKeys, // freeze me please
    contentType: ContentType.FRAMED_DATA,
    headerIvLength: ivLength,
    frameLength
  })

  const headerBytes = serializeMessageHeader(messageHeader)
  const headerBuffer = Buffer.from(<ArrayBuffer>headerBytes.buffer)
  const info = kdfInfo(messageHeader.algorithmId, messageHeader.messageId)
  const getCipher = kdfGetCipher(info)
  const headerIv = headerAuthIv(ivLength)
  const validateHeader = getCipher(headerIv)
  validateHeader.setAAD(headerBuffer)
  validateHeader.update(Buffer.alloc(0))
  validateHeader.final()
  const headerAuth = validateHeader.getAuthTag()

  return {
    getCipher,
    messageHeader,
    rawHeader: [headerBuffer, headerIv, headerAuth]
  }
}
