// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  WebCryptoAlgorithmSuite,
  KeyringWebCrypto,
  WebCryptoDefaultCryptographicMaterialsManager,
  getDecryptionHelper,
  GetSubtleDecrypt,
  needs,
  WebCryptoMaterialsManager,
  CommitmentPolicy,
  CommitmentPolicySuites,
  ClientOptions,
} from '@aws-crypto/material-management-browser'
import {
  deserializeSignature,
  MessageHeader,
  deserializeFactory,
  decodeBodyHeader,
  aadFactory,
  concatBuffers,
  der2raw,
  HeaderInfo,
  MessageHeaderV2,
} from '@aws-crypto/serialize'
import { fromUtf8, toUtf8 } from '@aws-sdk/util-utf8-browser'

const deserialize = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
const { messageAADContentString, messageAAD } = aadFactory(fromUtf8)

export interface DecryptResult {
  messageHeader: MessageHeader
  plaintext: Uint8Array
}

export async function _decrypt(
  { commitmentPolicy, maxEncryptedDataKeys }: ClientOptions,
  cmm: KeyringWebCrypto | WebCryptoMaterialsManager,
  ciphertext: Uint8Array
): Promise<DecryptResult> {
  /* Precondition: _decrypt needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')

  // buildDecrypt defaults this to false for backwards compatibility, so this is satisfied
  /* Precondition: _decrypt needs a valid maxEncryptedDataKeys. */
  needs(
    maxEncryptedDataKeys === false || maxEncryptedDataKeys >= 1,
    'Invalid maxEncryptedDataKeys value.'
  )

  /* If the cmm is a Keyring, wrap it with WebCryptoDefaultCryptographicMaterialsManager. */
  cmm =
    cmm instanceof KeyringWebCrypto
      ? new WebCryptoDefaultCryptographicMaterialsManager(cmm)
      : cmm

  const headerInfo = deserialize.deserializeMessageHeader(ciphertext, {
    maxEncryptedDataKeys,
  })
  if (headerInfo === false) throw new Error('Unable to parse Header')
  const { messageHeader, algorithmSuite } = headerInfo
  const { rawHeader, headerAuth } = headerInfo
  const { headerIv, headerAuthTag } = headerAuth
  const { encryptionContext, encryptedDataKeys, suiteId, messageId } =
    messageHeader

  // Very quick hex string
  const messageIdStr = [...messageId]
    .map((i) => (i > 15 ? i.toString(16) : '0' + i.toString(16)))
    .join('')

  /* Precondition: The parsed header algorithmSuite in _decrypt must be supported by the commitmentPolicy. */
  CommitmentPolicySuites.isDecryptEnabled(
    commitmentPolicy,
    algorithmSuite,
    messageIdStr
  )

  const suite = new WebCryptoAlgorithmSuite(suiteId)

  const material = await cmm.decryptMaterials({
    suite,
    encryptionContext,
    encryptedDataKeys,
  })

  /* Precondition: The material algorithmSuite returned to _decrypt must be supported by the commitmentPolicy. */
  CommitmentPolicySuites.isDecryptEnabled(
    commitmentPolicy,
    material.suite,
    messageIdStr
  )
  const { getDecryptInfo, subtleVerify, dispose } = await getDecryptionHelper(
    material
  )
  const getSubtleDecrypt = await getDecryptInfo(
    messageId,
    (messageHeader as MessageHeaderV2).suiteData
  )

  // The tag is appended to the Data
  await getSubtleDecrypt(headerIv, rawHeader)(headerAuthTag) // will throw if invalid

  const { plaintext, readPos } = await bodyDecrypt({
    buffer: ciphertext,
    getSubtleDecrypt,
    headerInfo,
  })

  dispose()

  if (subtleVerify) {
    const data = ciphertext.slice(0, readPos)
    const signatureInfo = ciphertext.slice(readPos)

    const derSignature = deserializeSignature(signatureInfo)
    const rawSignature = der2raw(derSignature, material.suite)

    const isValid = await subtleVerify(rawSignature, data)
    /* Postcondition: subtleVerify must validate the signature. */
    needs(isValid, 'Invalid Signature')
    return { messageHeader, plaintext }
  } else {
    return { messageHeader, plaintext }
  }
}

interface BodyDecryptOptions {
  buffer: Uint8Array
  getSubtleDecrypt: GetSubtleDecrypt
  headerInfo: HeaderInfo
}

interface FramedDecryptOptions extends BodyDecryptOptions {
  readPos: number
}

async function bodyDecrypt({
  buffer,
  getSubtleDecrypt,
  headerInfo,
}: BodyDecryptOptions) {
  let readPos =
    headerInfo.rawHeader.byteLength + headerInfo.headerAuth.headerAuthLength
  const clearBuffers: ArrayBuffer[] = []
  let sequenceNumber = 0
  // This is unfortunate, ideally the eslint no-constant-condition could be resolve
  // but at this time, I'm just going to disable this line
  // and leave a note to keep myself from replicating this kind of logic.
  /* eslint-disable no-constant-condition */
  while (true) {
    /* eslint-enable no-constant-condition */

    /* Keeping track of the sequence number myself. */
    sequenceNumber += 1

    const { clearBlob, frameInfo } = await framedDecrypt({
      buffer,
      getSubtleDecrypt,
      headerInfo,
      readPos,
    })

    /* Precondition: The sequenceNumber is required to monotonically increase, starting from 1.
     * This is to avoid a bad actor from abusing the sequence number on un-signed algorithm suites.
     * If the frame size matched the data format (say NDJSON),
     * then the data could be significantly altered just by rearranging the frames.
     * Non-framed data returns a sequenceNumber of 1.
     */
    needs(
      frameInfo.sequenceNumber === sequenceNumber,
      'Encrypted body sequence out of order.'
    )

    clearBuffers.push(clearBlob)
    readPos = frameInfo.readPos
    if (frameInfo.isFinalFrame) {
      const plaintext = concatBuffers(...clearBuffers)
      return { plaintext, readPos }
    }
  }
}

/* As we move to deprecate non-framed encrypt it is important to continue to support
 * non-framed decrypt.  The names not-withstanding, this supports non-framed decrypt
 * See decodeBodyHeader (it abstracts framed and non-framed body headers)
 */
async function framedDecrypt({
  buffer,
  getSubtleDecrypt,
  headerInfo,
  readPos,
}: FramedDecryptOptions) {
  const {
    messageHeader: { messageId },
  } = headerInfo
  const frameInfo = decodeBodyHeader(buffer, headerInfo, readPos)
  if (!frameInfo) throw new Error('Format Error')
  const cipherLength = frameInfo.contentLength + frameInfo.tagLength / 8
  const contentString = messageAADContentString(frameInfo)
  const messageAdditionalData = messageAAD(
    messageId,
    contentString,
    frameInfo.sequenceNumber,
    frameInfo.contentLength
  )
  const cipherBlob = buffer.slice(
    frameInfo.readPos,
    frameInfo.readPos + cipherLength
  )
  const clearBlob = await getSubtleDecrypt(
    frameInfo.iv,
    messageAdditionalData
  )(cipherBlob)
  frameInfo.readPos += cipherLength
  return { clearBlob, frameInfo }
}
