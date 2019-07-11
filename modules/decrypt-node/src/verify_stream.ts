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

// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream' // eslint-disable-line no-unused-vars
import { DecipherGCM } from 'crypto' // eslint-disable-line no-unused-vars
import {
  needs,
  GetVerify // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import {
  deserializeSignature,
  decodeBodyHeader,
  BodyHeader, // eslint-disable-line no-unused-vars
  HeaderInfo // eslint-disable-line no-unused-vars
} from '@aws-crypto/serialize'
import { ParseHeaderStream } from './parse_header_stream'
import { DecipherInfo } from './decipher_stream' // eslint-disable-line no-unused-vars

type AWSVerify = ReturnType<GetVerify>
const PortableTransformWithType = (<new (...args: any[]) => Transform>PortableTransform)

export interface VerifyInfo {
  headerInfo: HeaderInfo
  getDecipher: (iv: Uint8Array) => DecipherGCM
  dispose: () => void
  verify?: AWSVerify
}

export interface VerifyStreamOptions {
  maxBodySize?: number
}

interface VerifyState {
  buffer: Buffer
  authTagBuffer: Buffer
  currentFrame?: BodyHeader
  signatureInfo: Buffer
}

export class VerifyStream extends PortableTransformWithType {
  private _headerInfo!: HeaderInfo
  private _verifyState: VerifyState = {
    buffer: Buffer.alloc(0),
    authTagBuffer: Buffer.alloc(0),
    signatureInfo: Buffer.alloc(0)
  }
  private _verify?: AWSVerify
  private _maxBodySize?: number
  constructor ({ maxBodySize }: VerifyStreamOptions) {
    super()
    /* Precondition: MaxBodySize must be falsey or a number. */
    needs(!maxBodySize || typeof maxBodySize === 'number', 'Unsupported MaxBodySize.')
    Object.defineProperty(this, '_maxBodySize', { value: maxBodySize, enumerable: true })

    this.on('pipe', (source: ParseHeaderStream) => {
      /* Precondition: The source must a ParseHeaderStream emit the required events. */
      needs(source instanceof ParseHeaderStream, 'Unsupported source')
      source.once('VerifyInfo', (verifyInfo: VerifyInfo) => {
        const { getDecipher, verify, headerInfo, dispose } = verifyInfo
        const { messageId, contentType } = headerInfo.messageHeader
        /* If I have a verify, the header needs to be flushed through.
         * I do it here for initialize the verifier before I even
         * add the element to the object.
         */
        if (verify) {
          const { rawHeader, headerIv, headerAuthTag } = headerInfo
          ;[rawHeader, headerIv, headerAuthTag].forEach(e => verify.update(e))
        }
        Object.defineProperty(this, '_headerInfo', { value: headerInfo, enumerable: true })
        Object.defineProperty(this, '_verify', { value: verify, enumerable: true })

        const decipherInfo: DecipherInfo = {
          // @ts-ignore
          messageId: Buffer.from(messageId.buffer, messageId.byteOffset, messageId.byteLength),
          contentType,
          getDecipher,
          dispose
        }
        this.emit('DecipherInfo', decipherInfo)
      })
    })
  }

  _transform (chunk: Buffer, enc: string, callback: Function): any {
    /* Precondition: VerifyInfo must have initialized the stream. */
    needs(this._headerInfo, 'VerifyStream not configured, VerifyInfo event not yet received.')

    // BodyHeader
    const state = this._verifyState
    const { currentFrame } = state
    if (!currentFrame) {
      const { buffer } = state
      const frameBuffer = Buffer.concat([buffer, chunk])
      const frameHeader = decodeBodyHeader(frameBuffer, this._headerInfo, 0)
      if (!frameHeader) {
        // Need more data
        state.buffer = frameBuffer
        return callback()
      }

      /* Precondition: If maxBodySize was set I can not buffer more data than maxBodySize.
       * Before returning *any* cleartext, the stream **MUST** verify the decryption.
       * This means that I must buffer the message until the AuthTag is reached.
       */
      needs(!this._maxBodySize || this._maxBodySize >= frameHeader.contentLength, 'maxBodySize exceeded.')

      if (this._verify) {
        this._verify.update(frameBuffer.slice(0, frameHeader.readPos))
      }
      const tail = chunk.slice(frameHeader.readPos)
      this.emit('BodyInfo', frameHeader)
      state.currentFrame = frameHeader
      return setImmediate(() => this._transform(tail, enc, callback))
    }

    // Content
    const { contentLength } = currentFrame
    if (chunk.length && contentLength > 0) {
      if (contentLength > chunk.length) {
        currentFrame.contentLength -= chunk.length
        this.push(chunk)
        return callback()
      } else {
        const content = chunk.slice(0, contentLength)
        const tail = chunk.slice(content.length)
        this.push(content)
        currentFrame.contentLength = 0
        return setImmediate(() => this._transform(tail, enc, callback))
      }
    }

    // AuthTag
    const { tagLength } = currentFrame
    const tagLengthBytes = tagLength / 8
    const { authTagBuffer } = state
    if (chunk.length && tagLengthBytes > authTagBuffer.length) {
      const left = tagLengthBytes - authTagBuffer.length
      if (left > chunk.length) {
        state.authTagBuffer = Buffer.concat([authTagBuffer, chunk])
        return callback()
      } else {
        const finalAuthTagBuffer = Buffer.concat([authTagBuffer, chunk], tagLengthBytes)
        if (this._verify) {
          this._verify.update(finalAuthTagBuffer)
        }
        /* Reset state.
         * Ciphertext buffers and authTag buffers need to be cleared.
         */
        state.buffer = Buffer.alloc(0)
        state.currentFrame = undefined
        state.authTagBuffer = Buffer.alloc(0)
        /* After the final frame the file format is _much_ simpler.
         * Making sure the cascading if blocks fall to the signature can be tricky and brittle.
         * After the final frame, just moving on to concatenate the signature is much simpler.
         */
        if (currentFrame.isFinalFrame) {
          /* Overwriting the _transform function.
           * Data flow control is not handled here.
           */
          this._transform = (chunk: Buffer, _enc: string, callback: Function) => {
            if (chunk.length) {
              state.signatureInfo = Buffer.concat([state.signatureInfo, chunk])
            }

            callback()
          }
        }

        const tail = chunk.slice(left)
        /* The decipher_stream uses the `AuthTag` event to flush the accumulated frame.
         * This is because ciphertext should never be returned until it is verified.
         * i.e. the auth tag checked.
         * This can create an issue if the chucks and frame size are small.
         * If the verify stream continues processing and sends the next auth tag,
         * before the current auth tag has been completed.
         * This is basically a back pressure issue.
         * Since the frame size, and consequently the high water mark,
         * can not be know when the stream is created,
         * the internal stream state would need to be modified.
         * I assert that a simple callback is a simpler way to handle this.
         */
        const next = () => this._transform(tail, enc, callback)
        return this.emit('AuthTag', finalAuthTagBuffer, next)
      }
    }

    callback()
  }

  push (chunk: any, encoding?: string | undefined): boolean {
    // Typescript???? this._verify instanceof Verify is better....
    if (this._verify && chunk) {
      this._verify.update(chunk)
    }
    return super.push(chunk, encoding)
  }

  _flush (callback: Function) {
    /* Check for early return (Postcondition): If there is no verify stream do not attempt to verify. */
    if (!this._verify) return callback()
    const { signatureInfo } = this._verifyState
    const { buffer, byteOffset, byteLength } = deserializeSignature(signatureInfo)
    const signature = Buffer.from(buffer, byteOffset, byteLength)
    const isVerified = this._verify.awsCryptoVerify(signature)
    /* Postcondition: The signature must be valid. */
    needs(isVerified, 'Invalid Signature')
    callback()
  }
}
