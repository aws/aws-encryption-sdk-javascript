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

import {
  NodeDefaultCryptographicMaterialsManager, NodeAlgorithmSuite, AlgorithmSuiteIdentifier, // eslint-disable-line no-unused-vars
  KeyringNode, NodeEncryptionMaterial, getEncryptHelper, EncryptionContext, // eslint-disable-line no-unused-vars
  NodeMaterialsManager, // eslint-disable-line no-unused-vars
  needs
} from '@aws-crypto/material-management-node'
import { getFramedEncryptStream } from './framed_encrypt_stream'
import { SignatureStream } from './signature_stream'
import Duplexify from 'duplexify'
import { randomBytes } from 'crypto'
import {
  MessageHeader, // eslint-disable-line no-unused-vars
  serializeFactory, kdfInfo, ContentType, SerializationVersion, ObjectType,
  FRAME_LENGTH,
  MESSAGE_ID_LENGTH,
  Maximum
} from '@aws-crypto/serialize'

// @ts-ignore
import { pipeline } from 'readable-stream'
import { Duplex } from 'stream' // eslint-disable-line no-unused-vars

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const { serializeMessageHeader, headerAuthIv } = serializeFactory(fromUtf8)

export interface EncryptStreamInput {
  suiteId?: AlgorithmSuiteIdentifier
  encryptionContext?: EncryptionContext
  frameLength?: number
  plaintextLength?: number
}

/**
 * Takes a NodeDefaultCryptographicMaterialsManager or a KeyringNode that will
 * be wrapped in a NodeDefaultCryptographicMaterialsManager and returns a stream.
 *
 * @param cmm NodeMaterialsManager|KeyringNode
 * @param op EncryptStreamInput
 */
export function encryptStream (
  cmm: KeyringNode|NodeMaterialsManager,
  op: EncryptStreamInput = {}
): Duplex {
  const { suiteId, encryptionContext = {}, frameLength = FRAME_LENGTH } = op

  /* Precondition: The frameLength must be less than the maximum frame size Node.js stream. */
  needs(frameLength > 0 && Maximum.FRAME_SIZE >= frameLength, `frameLength out of bounds: 0 > frameLength >= ${Maximum.FRAME_SIZE}`)

  /* If the cmm is a Keyring, wrap it with NodeDefaultCryptographicMaterialsManager. */
  cmm = cmm instanceof KeyringNode
    ? new NodeDefaultCryptographicMaterialsManager(cmm)
    : cmm

  const suite = suiteId && new NodeAlgorithmSuite(suiteId)

  const wrappingStream = new Duplexify()

  cmm.getEncryptionMaterials({ suite, encryptionContext, frameLength })
    .then(async (material) => {
      const { dispose, getSigner } = getEncryptHelper(material)

      const { getCipher, messageHeader, rawHeader } = getEncryptionInfo(material, frameLength)

      wrappingStream.emit('MessageHeader', messageHeader)

      const encryptStream = getFramedEncryptStream(getCipher, messageHeader, dispose)
      const signatureStream = new SignatureStream(getSigner)

      pipeline(encryptStream, signatureStream)

      wrappingStream.setReadable(signatureStream)
      // Flush the rawHeader through the signatureStream
      rawHeader.forEach(buff => signatureStream.write(buff))

      // @ts-ignore until readable-stream exports v3 types...
      wrappingStream.setWritable(encryptStream)
    })
    .catch(err => wrappingStream.emit('error', err))

  return wrappingStream
}

export function getEncryptionInfo (material : NodeEncryptionMaterial, frameLength: number) {
  const { kdfGetCipher } = getEncryptHelper(material)
  const { encryptionContext } = material

  const messageId = randomBytes(MESSAGE_ID_LENGTH)
  const { id, ivLength } = material.suite
  const messageHeader: MessageHeader = Object.freeze({
    version: SerializationVersion.V1,
    type: ObjectType.CUSTOMER_AE_DATA,
    suiteId: id,
    messageId,
    encryptionContext,
    encryptedDataKeys: Object.freeze(material.encryptedDataKeys), // freeze me please
    contentType: ContentType.FRAMED_DATA,
    headerIvLength: ivLength,
    frameLength
  })

  const { buffer, byteOffset, byteLength } = serializeMessageHeader(messageHeader)
  const headerBuffer = Buffer.from(buffer, byteOffset, byteLength)
  const info = kdfInfo(messageHeader.suiteId, messageHeader.messageId)
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
