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
  WebCryptoAlgorithmSuite,
  KeyringWebCrypto,
  WebCryptoDefaultCryptographicMaterialsManager,
  getDecryptionHelper,
  GetSubtleDecrypt, // eslint-disable-line no-unused-vars
  needs,
  WebCryptoMaterialsManager // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'
import {
  deserializeSignature,
  MessageHeader, // eslint-disable-line no-unused-vars
  deserializeFactory,
  kdfInfo,
  decodeBodyHeader,
  aadFactory,
  concatBuffers,
  der2raw,
  HeaderInfo // eslint-disable-line no-unused-vars
} from '@aws-crypto/serialize'
import { fromUtf8, toUtf8 } from '@aws-sdk/util-utf8-browser'

const deserialize = deserializeFactory(toUtf8, WebCryptoAlgorithmSuite)
const { messageAADContentString, messageAAD } = aadFactory(fromUtf8)

export interface DecryptResult {
  messageHeader: MessageHeader
  clearMessage: Uint8Array
}

export async function decrypt (
  cmm: KeyringWebCrypto|WebCryptoMaterialsManager,
  ciphertext: Uint8Array
): Promise<DecryptResult> {
  /* If the cmm is a Keyring, wrap it with WebCryptoDefaultCryptographicMaterialsManager. */
  cmm = cmm instanceof KeyringWebCrypto
    ? new WebCryptoDefaultCryptographicMaterialsManager(cmm)
    : cmm

  const headerInfo = deserialize.deserializeMessageHeader(ciphertext)
  if (headerInfo === false) throw new Error('Unable to parse Header')
  const { messageHeader } = headerInfo
  const { rawHeader, headerIv, headerAuthTag } = headerInfo
  const { encryptionContext, encryptedDataKeys, suiteId, messageId } = messageHeader
  const suite = new WebCryptoAlgorithmSuite(suiteId)

  const { material } = await cmm.decryptMaterials({ suite, encryptionContext, encryptedDataKeys })
  const { kdfGetSubtleDecrypt, subtleVerify, dispose } = await getDecryptionHelper(material)
  const info = kdfInfo(suiteId, messageId)
  const getSubtleDecrypt = kdfGetSubtleDecrypt(info)

  // The tag is appended to the Data
  await getSubtleDecrypt(headerIv, rawHeader)(headerAuthTag) // will throw if invalid

  const { clearMessage, readPos } = await bodyDecrypt({ buffer: ciphertext, getSubtleDecrypt, headerInfo })

  dispose()

  if (subtleVerify) {
    const data = ciphertext.slice(0, readPos)
    const signatureInfo = ciphertext.slice(readPos)

    const derSignature = deserializeSignature(signatureInfo)
    const rawSignature = der2raw(derSignature, material.suite)

    const isValid = await subtleVerify(rawSignature, data)
    /* Postcondition: subtleVerify must validate the signature. */
    needs(isValid, 'Invalid Signature')
    return { messageHeader, clearMessage }
  } else {
    return { messageHeader, clearMessage }
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

async function bodyDecrypt ({ buffer, getSubtleDecrypt, headerInfo }: BodyDecryptOptions) {
  let readPos = headerInfo.headerIv.byteLength + headerInfo.rawHeader.byteLength + headerInfo.headerAuthTag.byteLength
  const clearBuffers: ArrayBuffer[] = []
  let sequenceNumber = 0
  while (true) {
    /* Keeping track of the sequence number myself. */
    sequenceNumber += 1

    const { clearBlob, frameInfo } = await framedDecrypt({ buffer, getSubtleDecrypt, headerInfo, readPos })

    /* Precondition: The sequenceNumber is required to monotonically increase, starting from 1.
     * This is to avoid a bad actor from abusing the sequence number on un-signed algorithm suites.
     * If the frame size matched the data format (say NDJSON),
     * then the data could be significantly altered just by rearranging the frames.
     * Non-framed data returns a sequenceNumber of 1.
     */
    needs(frameInfo.sequenceNumber === sequenceNumber, 'Encrypted body sequence out of order.')

    clearBuffers.push(clearBlob)
    readPos = frameInfo.readPos
    if (frameInfo.isFinalFrame) {
      const clearMessage = concatBuffers(...clearBuffers)
      return { clearMessage, readPos }
    }
  }
}

/* As we move to deprecate non-framed encrypt it is important to continue to support
 * non-framed decrypt.  The names not-withstanding, this supports non-framed decrypt
 * See decodeBodyHeader (it abstracts framed and non-framed body headers)
 */
async function framedDecrypt ({ buffer, getSubtleDecrypt, headerInfo, readPos }: FramedDecryptOptions) {
  const { messageHeader: { messageId } } = headerInfo
  const frameInfo = decodeBodyHeader(buffer, headerInfo, readPos)
  if (!frameInfo) throw new Error('Format Error')
  const cipherLength = frameInfo.contentLength + frameInfo.tagLength / 8
  const contentString = messageAADContentString(frameInfo)
  const messageAdditionalData = messageAAD(messageId, contentString, frameInfo.sequenceNumber, frameInfo.contentLength)
  const cipherBlob = buffer.slice(frameInfo.readPos, frameInfo.readPos + cipherLength)
  const clearBlob = await getSubtleDecrypt(frameInfo.iv, messageAdditionalData)(cipherBlob)
  frameInfo.readPos += cipherLength
  return { clearBlob, frameInfo }
}
