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
  WebCryptoAlgorithmSuite,
  WebCryptoCryptographicMaterialsManager,
  WebCryptoEncryptionRequest,
  EncryptionContext,
  AlgorithmSuiteIdentifier,
  getEncryptHelper
} from '@aws-crypto/material-management-browser'
import {serializeFactory, aadFactory, kdfInfo, concatBuffers, MessageHeader, SerializationVersion, ObjectType, ContentType} from '@aws-crypto/serialize'
import {fromUtf8} from '@aws-sdk/util-utf8-browser'
import {getWebCryptoBackend} from '@aws-crypto/web-crypto-backend'

const serialize = serializeFactory(fromUtf8)
const {messageAADContentString, messageAAD} = aadFactory(fromUtf8)

export interface EncryptInput {
  suiteId?: AlgorithmSuiteIdentifier
  encryptionContext?: EncryptionContext
  // frameLength?: number // Subtle Crypto functions are all one-shot, so frames and length are === plaintext.byteLength
  // plaintextLength?: number // Subtle Crypto functions are all one-shot, so frames and length are === plaintext.byteLength
}

export interface EncryptResult {
  messageHeader: MessageHeader
  cipherMessage: Uint8Array
}

export async function encrypt(
  cmm: WebCryptoCryptographicMaterialsManager,
  plaintext: Uint8Array,
  {suiteId, encryptionContext}: EncryptInput = {}
): Promise<EncryptResult> {
  const backend = await getWebCryptoBackend()
  if (!backend) throw new Error('No supported crypto backend')

  // Subtle Crypto functions are all one-shot so all the plaintext needs to be available.
  const plaintextLength = plaintext.byteLength
  const frameLength = plaintextLength + 1
  const suite = suiteId ? new WebCryptoAlgorithmSuite(suiteId) : new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)

  const encryptionRequest: WebCryptoEncryptionRequest = {
    suite,
    encryptionContext,
    frameLength,
    plaintextLength
  }
 
  const {material, context} = await cmm.getEncryptionMaterials(encryptionRequest)
  const {kdfGetSubtleEncrypt, subtleSign, dispose} = await getEncryptHelper(material)

  // Why is this here?
  const idLength = 16
  const messageId = await backend.randomValues(idLength)

  const {id, ivLength} = material.suite

  const messageHeader = {
    version: SerializationVersion.V1,
    type: ObjectType.CUSTOMER_AE_DATA,
    algorithmId: id,
    messageId,
    encryptionContext: context,
    encryptedDataKeys: material.encryptedDataKeys,
    contentType: ContentType.FRAMED_DATA,
    headerIvLength: ivLength,
    frameLength
  }

  const header = serialize.serializeMessageHeader(messageHeader)
  const info = kdfInfo(id, messageId)
  const getSubtleEncrypt = kdfGetSubtleEncrypt(info)

  const headerAuthIv = serialize.headerAuthIv(ivLength)
  const headerAuthTag = await getSubtleEncrypt(headerAuthIv, header)(new Uint8Array(0))

  const sequenceNumber = 1
  const frameIv = serialize.frameIv(ivLength, sequenceNumber)
  const finalFrameHeader = serialize.finalFrameHeader(sequenceNumber, frameIv, plaintextLength)
  const messageAdditionalData = messageAAD(
    messageId,
    messageAADContentString({contentType: messageHeader.contentType, isFinalFrame: true}),
    sequenceNumber,
    plaintextLength
  )

  const cipherBufferAndAuthTag = await getSubtleEncrypt(frameIv, messageAdditionalData)(plaintext)
  const cipherMessage = concatBuffers(
    header,
    headerAuthIv,
    headerAuthTag,
    finalFrameHeader,
    cipherBufferAndAuthTag
  )

  dispose()

  if (typeof subtleSign === 'function') {
    const signature = await subtleSign(cipherMessage)
    return {cipherMessage: concatBuffers(cipherMessage, signature), messageHeader}
  } else {
    return {cipherMessage, messageHeader}
  }
}
