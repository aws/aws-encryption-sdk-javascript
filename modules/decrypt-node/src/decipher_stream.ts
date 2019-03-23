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

// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream' // eslint-disable-line no-unused-vars
import { DecipherGCM } from 'crypto' // eslint-disable-line no-unused-vars
import { needs } from '@aws-crypto/material-management-node'
import {
  aadFactory,
  ContentType // eslint-disable-line no-unused-vars
} from '@aws-crypto/serialize'
import { VerifyStream } from './verify_stream'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const aadUtility = aadFactory(fromUtf8)
const PortableTransformWithType = (<new (...args: any[]) => Transform>PortableTransform)

export interface DecipherInfo {
  messageId: Buffer
  contentType: ContentType
  getDecipher: (iv: Uint8Array) => DecipherGCM
  dispose: () => void
}

interface DecipherState {
  decipher: DecipherGCM
  content: Buffer[]
  contentLength: number
}

export interface BodyInfo {
  iv: Buffer
  contentLength: number
  sequenceNumber: number
  isFinalFrame: boolean
}

const ioTick = () => new Promise(resolve => setImmediate(resolve))
const noop = () => {}

export function getDecipherStream () {
  let decipherInfo: DecipherInfo
  let decipherState: DecipherState = {} as any
  let pathologicalDrain: Function = noop
  let frameComplete: Function|false = false

  return new (class DecipherStream extends PortableTransformWithType {
    constructor () {
      super()
      this.on('pipe', (source: VerifyStream) => {
        /* Precondition: The source must emit the required events. */
        needs(source instanceof VerifyStream, 'Unsupported source')
        source
          .once('DecipherInfo', (info: DecipherInfo) => {
            decipherInfo = info
          })
          .on('BodyInfo', this._onBodyHeader)
          .on('AuthTag', this._onAuthTag)
      })
    }

    _onBodyHeader = ({ iv, contentLength, sequenceNumber, isFinalFrame }: BodyInfo) => {
      /* Precondition: decipherInfo must be set before BodyInfo is sent. */
      needs(decipherInfo, 'Malformed State.')
      /* Precondition: Ciphertext must not be flowing before a BodyHeader is processed. */
      needs(!decipherState.decipher, 'Malformed State.')

      const { messageId, contentType, getDecipher } = decipherInfo
      const aadString = aadUtility.messageAADContentString({ contentType, isFinalFrame })
      const messageAAD = aadUtility.messageAAD(messageId, aadString, sequenceNumber, contentLength)
      const decipher = getDecipher(iv)
        .setAAD(Buffer.from(messageAAD.buffer, messageAAD.byteOffset, messageAAD.byteLength))
      const content: Buffer[] = []
      decipherState = { decipher, content, contentLength }
    }

    _transform (chunk: any, _encoding: string, callback: Function) {
      /* Precondition: BodyHeader must be parsed before frame data. */
      needs(decipherState.decipher, 'Malformed State.')

      decipherState.contentLength -= chunk.length
      /* Precondition: Only content should be transformed, so the lengths must always match.
       * The BodyHeader and AuthTag are striped in the VerifyStream and passed in
       * through events.  This means that if I receive a chunk without havening reset
       * the content accumulation events are out of order.  Panic.
       */
      needs(decipherState.contentLength >= 0, 'Lengths do not match')
      const { content } = decipherState
      content.push(chunk)
      if (decipherState.contentLength > 0) {
        // More data to this frame
        callback()
      } else {
        // The frame is full, waiting for `AuthTag`
        // event to decrypt and forward the clear frame
        frameComplete = callback
      }
    }

    _read (size: number) {
      /* The _onAuthTag decrypts and pushes the encrypted frame.
       * If this.push returns false then this stream
       * should wait until the destination stream calls read.
       * This means that _onAuthTag needs to wait for some
       * indeterminate time.  I create a closure around
       * the resolution function for a promise that
       * is created in _onAuthTag.  This way
       * here in _read (the implementation of read)
       * if a frame is being pushed, we can release
       * it.
       */
      pathologicalDrain()
      pathologicalDrain = noop

      super._read(size)
    }

    _onAuthTag = async (authTag: Buffer) => {
      const { decipher, content, contentLength } = decipherState
      /* Precondition: _onAuthTag must be called only after a frame has been accumulated. */
      needs(frameComplete, 'AuthTag before frame.')
      /* Precondition: I must have received all content for this frame. */
      needs(contentLength === 0, 'Lengths do not match')

      // flush content from state.
      decipherState = {} as any

      decipher.setAuthTag(authTag)

      const clear: Buffer[] = []
      for (const cipherChunk of content) {
        const clearChunk = decipher.update(cipherChunk)
        clear.push(clearChunk)
        await ioTick()
      }

      // If the authTag is not valid this will throw
      const tail = decipher.final()
      clear.push(tail)

      for (const clearChunk of clear) {
        if (!this.push(clearChunk)) {
          /* back pressure: if push returns false, wait until _read
           * has been called.
           */
          await new Promise(resolve => { pathologicalDrain = resolve })
        }
      }

      if (!frameComplete) throw new Error('AuthTag before frame.') // this is for Typescript type guards
      // This frame is complete. Notify _transform to continue
      frameComplete()
      // reset for next frame.
      frameComplete = false
    }

    _destroy () {
      // It is possible to have to destroy the stream before
      // decipherInfo is set.  Especially if the HeaderAuth
      // is not valid.
      decipherInfo && decipherInfo.dispose()
    }
  })()
}
