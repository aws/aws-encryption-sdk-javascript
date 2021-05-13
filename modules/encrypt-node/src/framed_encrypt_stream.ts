// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  serializeFactory,
  aadFactory,
  MessageHeader,
  Maximum,
} from '@aws-crypto/serialize'
// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream'
import {
  GetCipher,
  AwsEsdkJsCipherGCM,
  needs,
  NodeAlgorithmSuite,
} from '@aws-crypto/material-management-node'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const serialize = serializeFactory(fromUtf8)
const { finalFrameHeader, frameHeader } = serialize
const aadUtility = aadFactory(fromUtf8)

interface AccumulatingFrame {
  contentLength: number
  content: Buffer[]
  sequenceNumber: number
}

interface EncryptFrame {
  content: Buffer[]
  bodyHeader: Buffer
  headerSent?: boolean
  cipher: AwsEsdkJsCipherGCM
  isFinalFrame: boolean
}
const PortableTransformWithType = PortableTransform as new (
  ...args: any[]
) => Transform

const ioTick = async () => new Promise((resolve) => setImmediate(resolve))
const noop = () => {} // eslint-disable-line @typescript-eslint/no-empty-function
type ErrBack = (err?: Error) => void

export function getFramedEncryptStream(
  getCipher: GetCipher,
  messageHeader: MessageHeader,
  dispose: () => void,
  {
    plaintextLength,
    suite,
  }: { plaintextLength?: number; suite: NodeAlgorithmSuite }
) {
  let accumulatingFrame: AccumulatingFrame = {
    contentLength: 0,
    content: [],
    sequenceNumber: 1,
  }
  let pathologicalDrain: (reason?: any) => void = noop
  const { frameLength } = messageHeader

  /* Precondition: plaintextLength must be within bounds.
   * The Maximum.BYTES_PER_MESSAGE is set to be within Number.MAX_SAFE_INTEGER
   * See serialize/identifiers.ts enum Maximum for more details.
   */
  needs(
    !plaintextLength ||
      (plaintextLength >= 0 && Maximum.BYTES_PER_MESSAGE >= plaintextLength),
    'plaintextLength out of bounds.'
  )

  /* Keeping the messageHeader, accumulatingFrame and pathologicalDrain private is the intention here.
   * It is already unlikely that these values could be touched in the current composition of streams,
   * but a different composition may change this.
   * Since we are handling the plain text here, it seems prudent to take extra measures.
   */
  return new (class FramedEncryptStream extends PortableTransformWithType {
    _transform(chunk: Buffer, encoding: string, callback: ErrBack) {
      const contentLeft = frameLength - accumulatingFrame.contentLength

      /* Precondition: Must not process more than plaintextLength.
       * The plaintextLength is the MAXIMUM value that can be encrypted.
       */
      needs(
        !plaintextLength || (plaintextLength -= chunk.length) >= 0,
        'Encrypted data exceeded plaintextLength.'
      )

      /* Check for early return (Postcondition): Have not accumulated a frame. */
      if (contentLeft > chunk.length) {
        // eat more
        accumulatingFrame.contentLength += chunk.length
        accumulatingFrame.content.push(chunk)
        return callback()
      }

      accumulatingFrame.contentLength += contentLeft
      accumulatingFrame.content.push(chunk.slice(0, contentLeft))

      // grab the tail
      const tail = chunk.slice(contentLeft)

      const encryptFrame = getEncryptFrame({
        pendingFrame: accumulatingFrame,
        messageHeader,
        getCipher,
        isFinalFrame: false,
        suite,
      })

      // Reset frame state for next frame
      const { sequenceNumber } = accumulatingFrame
      accumulatingFrame = {
        contentLength: 0,
        content: [],
        sequenceNumber: sequenceNumber + 1,
      }

      this._flushEncryptFrame(encryptFrame)
        .then(() => this._transform(tail, encoding, callback))
        .catch(callback)
    }

    _flush(callback: ErrBack) {
      const encryptFrame = getEncryptFrame({
        pendingFrame: accumulatingFrame,
        messageHeader,
        getCipher,
        isFinalFrame: true,
        suite,
      })

      this._flushEncryptFrame(encryptFrame)
        .then(() => callback())
        .catch(callback)
    }

    _destroy() {
      dispose()
    }

    _read(size: number) {
      super._read(size)
      /* The _flushEncryptFrame encrypts and pushes the frame.
       * If this.push returns false then this stream
       * should wait until the destination stream calls read.
       * This means that _flushEncryptFrame needs to wait for some
       * indeterminate time.  I create a closure around
       * the resolution function for a promise that
       * is created in _flushEncryptFrame.  This way
       * here in _read (the implementation of read)
       * if a frame is being pushed, we can release
       * it.
       */
      pathologicalDrain()
      pathologicalDrain = noop
    }

    async _flushEncryptFrame(encryptingFrame: EncryptFrame) {
      const { content, cipher, bodyHeader, isFinalFrame } = encryptingFrame

      this.push(bodyHeader)

      let frameSize = 0
      const cipherContent: Buffer[] = []
      for (const clearChunk of content) {
        const cipherText = cipher.update(clearChunk)
        frameSize += cipherText.length
        cipherContent.push(cipherText)
        await ioTick()
      }

      /* Finalize the cipher and handle any tail. */
      const tail = cipher.final()
      frameSize += tail.length
      cipherContent.push(tail)
      /* Push the authTag onto the end.  Yes, I am abusing the name. */
      cipherContent.push(cipher.getAuthTag())

      needs(
        frameSize === frameLength || (isFinalFrame && frameLength >= frameSize),
        'Malformed frame'
      )

      for (const cipherText of cipherContent) {
        if (!this.push(cipherText)) {
          /* back pressure: if push returns false, wait until _read
           * has been called.
           */
          await new Promise((resolve) => {
            pathologicalDrain = resolve
          })
        }
      }

      if (isFinalFrame) this.push(null)
    }
  })()
}

type EncryptFrameInput = {
  pendingFrame: AccumulatingFrame
  messageHeader: MessageHeader
  getCipher: GetCipher
  isFinalFrame: boolean
  suite: NodeAlgorithmSuite
}

export function getEncryptFrame(input: EncryptFrameInput): EncryptFrame {
  const { pendingFrame, messageHeader, getCipher, isFinalFrame, suite } = input
  const { sequenceNumber, contentLength, content } = pendingFrame
  const { frameLength, contentType, messageId } = messageHeader
  /* Precondition: The content length MUST correlate with the frameLength.
   * In the case of a regular frame,
   * the content length MUST strictly equal the frame length.
   * In the case of the final frame,
   * it MUST NOT be larger than the frame length.
   */
  needs(
    frameLength === contentLength ||
      (isFinalFrame && frameLength >= contentLength),
    `Malformed frame length and content length: ${JSON.stringify({
      frameLength,
      contentLength,
      isFinalFrame,
    })}`
  )
  const frameIv = serialize.frameIv(suite.ivLength, sequenceNumber)
  const bodyHeader = Buffer.from(
    isFinalFrame
      ? finalFrameHeader(sequenceNumber, frameIv, contentLength)
      : frameHeader(sequenceNumber, frameIv)
  )
  const contentString = aadUtility.messageAADContentString({
    contentType,
    isFinalFrame,
  })
  const { buffer, byteOffset, byteLength } = aadUtility.messageAAD(
    messageId,
    contentString,
    sequenceNumber,
    contentLength
  )
  const cipher = getCipher(frameIv)
  cipher.setAAD(Buffer.from(buffer, byteOffset, byteLength))

  return { content, cipher, bodyHeader, isFinalFrame }
}
