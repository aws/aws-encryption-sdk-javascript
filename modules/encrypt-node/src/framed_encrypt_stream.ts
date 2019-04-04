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
  serializeFactory, aadFactory,
  MessageHeader // eslint-disable-line no-unused-vars
} from '@aws-crypto/serialize'
// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { CipherGCM } from 'crypto' // eslint-disable-line no-unused-vars
import { Transform } from 'stream' // eslint-disable-line no-unused-vars
import { needs } from '@aws-crypto/material-management-node'

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
  cipher: CipherGCM,
  isFinalFrame: boolean
}

const ioTick = () => new Promise(resolve => setImmediate(resolve))
type ErrBack = (err?: Error) => void

export function getFramedEncryptStream (getCipher: GetCipher, messageHeader: MessageHeader, dispose: Function) {
  let accumulatingFrame: AccumulatingFrame = { contentLength: 0, content: [], sequenceNumber: 1 }
  let pathologicalDrain: Function|false = false
  const { frameLength } = messageHeader

  return new (class FramedEncryptStream extends (<new (...args: any[]) => Transform>PortableTransform) {
    _transform (chunk: Buffer, encoding: string, callback: ErrBack) {
      const contentLeft = frameLength - accumulatingFrame.contentLength

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
        isFinalFrame: false
      })

      // Reset frame state for next frame
      const { sequenceNumber } = accumulatingFrame
      accumulatingFrame = {
        contentLength: 0,
        content: [],
        sequenceNumber: sequenceNumber + 1
      }

      this._flushEncryptFrame(encryptFrame)
        .then(() => this._transform(tail, encoding, callback))
        .catch(callback)
    }

    _flush (callback: ErrBack) {
      const encryptFrame = getEncryptFrame({
        pendingFrame: accumulatingFrame,
        messageHeader,
        getCipher,
        isFinalFrame: true
      })

      this._flushEncryptFrame(encryptFrame)
        .then(() => callback())
        .catch(callback)
    }

    _destroy () {
      dispose()
    }

    _read (size: number) {
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
      if (pathologicalDrain) {
        pathologicalDrain()
        pathologicalDrain = false
      }
    }

    async _flushEncryptFrame (encryptingFrame: EncryptFrame) {
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

      needs(frameSize === frameLength || isFinalFrame, 'Malformed frame')

      for (const cipherText of cipherContent) {
        if (!this.push(cipherText)) {
          /* back pressure: if push returns false, wait until _read
           * has been called.
           */
          await new Promise(resolve => { pathologicalDrain = resolve })
        }
      }

      if (isFinalFrame) this.push(null)
    }
  })()
}

type GetCipher = (iv: Uint8Array) => CipherGCM

type EncryptFrameInput = {
  pendingFrame: AccumulatingFrame,
  messageHeader: MessageHeader,
  getCipher: GetCipher,
  isFinalFrame: boolean
}

export function getEncryptFrame (input: EncryptFrameInput): EncryptFrame {
  const { pendingFrame, messageHeader, getCipher, isFinalFrame } = input
  const { sequenceNumber, contentLength, content } = pendingFrame
  const frameIv = serialize.frameIv(messageHeader.headerIvLength, sequenceNumber)
  const bodyHeader = Buffer.from(isFinalFrame
    ? finalFrameHeader(sequenceNumber, frameIv, contentLength)
    : frameHeader(sequenceNumber, frameIv))
  const { contentType, messageId } = messageHeader
  const contentString = aadUtility.messageAADContentString({ contentType, isFinalFrame })
  const {buffer, byteOffset, byteLength} = aadUtility.messageAAD(messageId, contentString, sequenceNumber, contentLength)
  const cipher = getCipher(frameIv)
  cipher.setAAD(Buffer.from(buffer, byteOffset, byteLength))

  return { content, cipher, bodyHeader, isFinalFrame }
}
