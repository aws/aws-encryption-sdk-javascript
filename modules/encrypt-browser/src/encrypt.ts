// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  WebCryptoAlgorithmSuite,
  WebCryptoDefaultCryptographicMaterialsManager,
  WebCryptoEncryptionRequest,
  EncryptionContext,
  AlgorithmSuiteIdentifier,
  getEncryptHelper,
  KeyringWebCrypto,
  needs,
  WebCryptoMaterialsManager,
  CommitmentPolicy,
  CommitmentPolicySuites,
  MessageFormat,
  ClientOptions,
} from '@aws-crypto/material-management-browser'
import {
  serializeFactory,
  aadFactory,
  concatBuffers,
  MessageHeader,
  serializeSignatureInfo,
  FRAME_LENGTH,
  raw2der,
  Maximum,
  MessageIdLength,
  serializeMessageHeaderAuth,
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

export async function _encrypt(
  { commitmentPolicy, maxEncryptedDataKeys }: ClientOptions,
  cmm: KeyringWebCrypto | WebCryptoMaterialsManager,
  plaintext: Uint8Array,
  {
    suiteId,
    encryptionContext = {},
    frameLength = FRAME_LENGTH,
  }: EncryptInput = {}
): Promise<EncryptResult> {
  /* Precondition: _encrypt needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')

  // buildEncrypt defaults this to false for backwards compatibility, so this is satisfied
  /* Precondition: _encrypt needs a valid maxEncryptedDataKeys. */
  needs(
    maxEncryptedDataKeys === false || maxEncryptedDataKeys >= 1,
    'Invalid maxEncryptedDataKeys value.'
  )

  /* Precondition: The frameLength must be less than the maximum frame size for browser encryption. */
  needs(
    frameLength > 0 && Maximum.FRAME_SIZE >= frameLength,
    `frameLength out of bounds: 0 > frameLength >= ${Maximum.FRAME_SIZE}`
  )

  const backend = await getWebCryptoBackend()
  if (!backend) throw new Error('No supported crypto backend')

  /* If the cmm is a Keyring, wrap it with WebCryptoDefaultCryptographicMaterialsManager. */
  cmm =
    cmm instanceof KeyringWebCrypto
      ? new WebCryptoDefaultCryptographicMaterialsManager(cmm)
      : cmm

  // Subtle Crypto functions are all one-shot so all the plaintext needs to be available.
  const plaintextLength = plaintext.byteLength
  const suite = suiteId && new WebCryptoAlgorithmSuite(suiteId)

  /* Precondition: Only request WebCryptoEncryptionMaterial for algorithm suites supported in commitmentPolicy. */
  CommitmentPolicySuites.isEncryptEnabled(commitmentPolicy, suite)

  const encryptionRequest: WebCryptoEncryptionRequest = {
    suite,
    encryptionContext,
    plaintextLength,
    commitmentPolicy,
  }

  const material = await cmm.getEncryptionMaterials(encryptionRequest)

  /* Precondition: Only use WebCryptoEncryptionMaterial for algorithm suites supported in commitmentPolicy. */
  CommitmentPolicySuites.isEncryptEnabled(commitmentPolicy, material.suite)

  /* Precondition: _encrypt encryption materials must not exceed maxEncryptedDataKeys */
  needs(
    maxEncryptedDataKeys === false ||
      material.encryptedDataKeys.length <= maxEncryptedDataKeys,
    'maxEncryptedDataKeys exceeded.'
  )

  const { getEncryptInfo, subtleSign, dispose } = await getEncryptHelper(
    material
  )

  const versionString = MessageFormat[material.suite.messageFormat] as any
  const messageIdLength = parseInt(MessageIdLength[versionString], 10)
  /* Precondition UNTESTED: WebCrypto suites must result is some messageIdLength. */
  needs(messageIdLength > 0, 'Algorithm suite has unknown message format.')

  const messageId = await backend.randomValues(messageIdLength)

  const { ivLength } = material.suite

  const { getSubtleEncrypt, keyCommitment } = await getEncryptInfo(messageId)

  const messageHeader = serialize.buildMessageHeader({
    suite: material.suite,
    encryptedDataKeys: material.encryptedDataKeys,
    encryptionContext: material.encryptionContext,
    messageId,
    frameLength,
    suiteData: keyCommitment,
  })

  const header = serialize.serializeMessageHeader(messageHeader)

  const headerIv = serialize.headerAuthIv(ivLength)
  const headerAuthTag = new Uint8Array(
    await getSubtleEncrypt(headerIv, header)(new Uint8Array(0))
  )

  const numberOfFrames = Math.ceil(plaintextLength / frameLength)
  /* The final frame has a variable length.
   * The value needs to be known, but should only be calculated once.
   * So I calculate how much of a frame I should have at the end.
   * This value will NEVER be larger than the frameLength.
   */
  const finalFrameLength =
    frameLength - (numberOfFrames * frameLength - plaintextLength)
  const bodyContent = []

  for (
    let sequenceNumber = 1;
    numberOfFrames >= sequenceNumber;
    sequenceNumber += 1
  ) {
    const frameIv = serialize.frameIv(ivLength, sequenceNumber)
    const isFinalFrame = sequenceNumber === numberOfFrames
    const frameHeader = isFinalFrame
      ? serialize.finalFrameHeader(sequenceNumber, frameIv, finalFrameLength)
      : serialize.frameHeader(sequenceNumber, frameIv)
    const contentString = messageAADContentString({
      contentType: messageHeader.contentType,
      isFinalFrame,
    })
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
    const cipherBufferAndAuthTag = await getSubtleEncrypt(
      frameIv,
      messageAdditionalData
    )(framePlaintext)

    bodyContent.push(frameHeader, cipherBufferAndAuthTag)
  }

  const result = concatBuffers(
    header,
    serializeMessageHeaderAuth({
      headerIv,
      headerAuthTag,
      messageHeader,
    }),
    ...bodyContent
  )

  dispose()

  if (typeof subtleSign === 'function') {
    const signatureArrayBuffer = await subtleSign(result)
    const derSignature = raw2der(
      new Uint8Array(signatureArrayBuffer),
      material.suite
    )
    const signatureInfo = serializeSignatureInfo(derSignature)
    return { result: concatBuffers(result, signatureInfo), messageHeader }
  } else {
    return { result: result, messageHeader }
  }
}
