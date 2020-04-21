// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  WebCryptoAlgorithmSuite,
  WebCryptoDefaultCryptographicMaterialsManager, // eslint-disable-line no-unused-vars
  WebCryptoEncryptionRequest, // eslint-disable-line no-unused-vars
  EncryptionContext, // eslint-disable-line no-unused-vars
  AlgorithmSuiteIdentifier,
  getEncryptHelper,
  KeyringWebCrypto,
  needs,
  WebCryptoMaterialsManager // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'
import {
  serializeFactory,
  aadFactory,
  kdfInfo,
  concatBuffers,
  MessageHeader, // eslint-disable-line no-unused-vars
  SerializationVersion,
  ObjectType,
  ContentType,
  serializeSignatureInfo,
  FRAME_LENGTH,
  MESSAGE_ID_LENGTH,
  raw2der,
  Maximum
} from '@aws-crypto/serialize'
import { fromUtf8 } from '@aws-sdk/util-utf8-browser'
import { getWebCryptoBackend } from '@aws-crypto/web-crypto-backend'

const serialize = serializeFactory(fromUtf8)
const { messageAADContentString, messageAAD } = aadFactory(fromUtf8)

export interface EncryptInput {
  suiteId?: AlgorithmSuiteIdentifier
  encryptionContext?: EncryptionContext
  frameLength?: number
  // plaintextLength?: number // Subtle Crypto functions are all one-shot, so frames and length are === plaintext.byteLength
}

export interface EncryptResult {
  messageHeader: MessageHeader
  result: Uint8Array
}

export async function encrypt (
  cmm: KeyringWebCrypto|WebCryptoMaterialsManager,
  plaintext: Uint8Array,
  { suiteId, encryptionContext = {}, frameLength = FRAME_LENGTH }: EncryptInput = {}
): Promise<EncryptResult> {
  /* Precondition: The frameLength must be less than the maximum frame size for browser encryption. */
  needs(frameLength > 0 && Maximum.FRAME_SIZE >= frameLength, `frameLength out of bounds: 0 > frameLength >= ${Maximum.FRAME_SIZE}`)

  const backend = await getWebCryptoBackend()
  if (!backend) throw new Error('No supported crypto backend')

  /* If the cmm is a Keyring, wrap it with WebCryptoDefaultCryptographicMaterialsManager. */
  cmm = cmm instanceof KeyringWebCrypto
    ? new WebCryptoDefaultCryptographicMaterialsManager(cmm)
    : cmm

  // Subtle Crypto functions are all one-shot so all the plaintext needs to be available.
  const plaintextLength = plaintext.byteLength
  const suite = suiteId ? new WebCryptoAlgorithmSuite(suiteId) : new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)

  const encryptionRequest: WebCryptoEncryptionRequest = {
    suite,
    encryptionContext,
    plaintextLength
  }

  const material = await cmm.getEncryptionMaterials(encryptionRequest)
  const { kdfGetSubtleEncrypt, subtleSign, dispose } = await getEncryptHelper(material)

  const messageId = await backend.randomValues(MESSAGE_ID_LENGTH)

  const { id, ivLength } = material.suite

  const messageHeader: MessageHeader = {
    version: SerializationVersion.V1,
    type: ObjectType.CUSTOMER_AE_DATA,
    suiteId: id,
    messageId,
    encryptionContext: material.encryptionContext,
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

  const numberOfFrames = Math.ceil(plaintextLength / frameLength)
  /* The final frame has a variable length.
   * The value needs to be known, but should only be calculated once.
   * So I calculate how much of a frame I should have at the end.
   * This value will NEVER be larger than the frameLength.
   */
  const finalFrameLength = frameLength - ((numberOfFrames * frameLength) - plaintextLength)
  const bodyContent = []

  for (let sequenceNumber = 1; numberOfFrames >= sequenceNumber; sequenceNumber += 1) {
    const frameIv = serialize.frameIv(ivLength, sequenceNumber)
    const isFinalFrame = sequenceNumber === numberOfFrames
    const frameHeader = isFinalFrame
      ? serialize.finalFrameHeader(sequenceNumber, frameIv, finalFrameLength)
      : serialize.frameHeader(sequenceNumber, frameIv)
    const contentString = messageAADContentString({ contentType: messageHeader.contentType, isFinalFrame })
    const messageAdditionalData = messageAAD(
      messageId,
      contentString,
      sequenceNumber,
      isFinalFrame ? finalFrameLength : frameLength
    )

    /* Slicing an ArrayBuffer in a browser is suboptimal.
     * It makes a copy.s
     * So I just make a new view for the length of the frame.
     */
    const framePlaintext = new Uint8Array(
      plaintext.buffer,
      (sequenceNumber - 1) * frameLength,
      isFinalFrame ? finalFrameLength : frameLength
    )
    const cipherBufferAndAuthTag = await getSubtleEncrypt(frameIv, messageAdditionalData)(framePlaintext)

    bodyContent.push(frameHeader, cipherBufferAndAuthTag)
  }

  const result = concatBuffers(
    header,
    headerAuthIv,
    headerAuthTag,
    ...bodyContent
  )

  dispose()

  if (typeof subtleSign === 'function') {
    const signatureArrayBuffer = await subtleSign(result)
    const derSignature = raw2der(new Uint8Array(signatureArrayBuffer), material.suite)
    const signatureInfo = serializeSignatureInfo(derSignature)
    return { result: concatBuffers(result, signatureInfo), messageHeader }
  } else {
    return { result: result, messageHeader }
  }
}
