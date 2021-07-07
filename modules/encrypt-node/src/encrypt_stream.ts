// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeDefaultCryptographicMaterialsManager,
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringNode,
  NodeEncryptionMaterial,
  getEncryptHelper,
  EncryptionContext,
  NodeMaterialsManager,
  needs,
  CommitmentPolicy,
  CommitmentPolicySuites,
  MessageFormat,
  ClientOptions,
} from '@aws-crypto/material-management-node'
import { getFramedEncryptStream } from './framed_encrypt_stream'
import { SignatureStream } from './signature_stream'
import Duplexify from 'duplexify'
import { randomBytes } from 'crypto'
import {
  serializeFactory,
  FRAME_LENGTH,
  Maximum,
  MessageIdLength,
  serializeMessageHeaderAuth,
} from '@aws-crypto/serialize'

// @ts-ignore
import { pipeline } from 'readable-stream'
import { Duplex } from 'stream'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const { serializeMessageHeader, headerAuthIv, buildMessageHeader } =
  serializeFactory(fromUtf8)

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
 * @param commitmentPolicy
 * @param maxEncryptedDataKeys
 * @param cmm NodeMaterialsManager|KeyringNode
 * @param op EncryptStreamInput
 */
export function _encryptStream(
  { commitmentPolicy, maxEncryptedDataKeys }: ClientOptions,
  cmm: KeyringNode | NodeMaterialsManager,
  op: EncryptStreamInput = {}
): Duplex {
  /* Precondition: encryptStream needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')

  // buildEncrypt defaults this to false for backwards compatibility, so this is satisfied
  /* Precondition: encryptStream needs a valid maxEncryptedDataKeys. */
  needs(
    maxEncryptedDataKeys === false || maxEncryptedDataKeys >= 1,
    'Invalid maxEncryptedDataKeys value.'
  )

  const {
    suiteId,
    encryptionContext = {},
    frameLength = FRAME_LENGTH,
    plaintextLength,
  } = op

  /* Precondition: The frameLength must be less than the maximum frame size Node.js stream. */
  needs(
    frameLength > 0 && Maximum.FRAME_SIZE >= frameLength,
    `frameLength out of bounds: 0 > frameLength >= ${Maximum.FRAME_SIZE}`
  )

  /* If the cmm is a Keyring, wrap it with NodeDefaultCryptographicMaterialsManager. */
  cmm =
    cmm instanceof KeyringNode
      ? new NodeDefaultCryptographicMaterialsManager(cmm)
      : cmm

  const suite = suiteId && new NodeAlgorithmSuite(suiteId)

  /* Precondition: Only request NodeEncryptionMaterial for algorithm suites supported in commitmentPolicy. */
  CommitmentPolicySuites.isEncryptEnabled(commitmentPolicy, suite)

  const wrappingStream = new Duplexify()

  cmm
    .getEncryptionMaterials({
      suite,
      encryptionContext,
      plaintextLength,
      commitmentPolicy,
    })
    .then(async (material) => {
      /* Precondition: Only use NodeEncryptionMaterial for algorithm suites supported in commitmentPolicy. */
      CommitmentPolicySuites.isEncryptEnabled(commitmentPolicy, material.suite)

      /* Precondition: _encryptStream encryption materials must not exceed maxEncryptedDataKeys */
      needs(
        maxEncryptedDataKeys === false ||
          material.encryptedDataKeys.length <= maxEncryptedDataKeys,
        'maxEncryptedDataKeys exceeded.'
      )

      const { getCipher, messageHeader, rawHeader, dispose, getSigner } =
        getEncryptionInfo(material, frameLength)

      wrappingStream.emit('MessageHeader', messageHeader)

      const encryptStream = getFramedEncryptStream(
        getCipher,
        messageHeader,
        dispose,
        { plaintextLength, suite: material.suite }
      )
      const signatureStream = new SignatureStream(getSigner)

      pipeline(encryptStream, signatureStream)

      wrappingStream.setReadable(signatureStream)
      // Flush the rawHeader through the signatureStream
      rawHeader.forEach((buff) => signatureStream.write(buff))

      // @ts-ignore until readable-stream exports v3 types...
      wrappingStream.setWritable(encryptStream)
    })
    .catch((err) => wrappingStream.emit('error', err))

  return wrappingStream
}

export function getEncryptionInfo(
  material: NodeEncryptionMaterial,
  frameLength: number
) {
  const { getCipherInfo, dispose, getSigner } = getEncryptHelper(material)
  const { suite, encryptionContext, encryptedDataKeys } = material
  const { ivLength, messageFormat } = material.suite

  const versionString = MessageFormat[messageFormat] as any
  const messageIdLength = parseInt(MessageIdLength[versionString], 10)
  /* Precondition UNTESTED: Node suites must result is some messageIdLength. */
  needs(messageIdLength > 0, 'Algorithm suite has unknown message format.')
  const messageId = randomBytes(messageIdLength)

  const { getCipher, keyCommitment } = getCipherInfo(messageId)

  const messageHeader = buildMessageHeader({
    suite: suite,
    encryptedDataKeys,
    encryptionContext,
    messageId,
    frameLength,
    suiteData: keyCommitment,
  })

  const { buffer, byteOffset, byteLength } =
    serializeMessageHeader(messageHeader)
  const headerBuffer = Buffer.from(buffer, byteOffset, byteLength)
  const headerIv = headerAuthIv(ivLength)
  const validateHeader = getCipher(headerIv)
  validateHeader.setAAD(headerBuffer)
  validateHeader.update(Buffer.alloc(0))
  validateHeader.final()
  const headerAuthTag = validateHeader.getAuthTag()

  return {
    getCipher,
    dispose,
    getSigner,
    messageHeader,
    rawHeader: [
      headerBuffer,
      serializeMessageHeaderAuth({ headerIv, headerAuthTag, messageHeader }),
    ],
  }
}
