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
import { Decipher, Verify } from 'crypto' // eslint-disable-line no-unused-vars
import { needs } from '@aws-crypto/material-management-node'
import {
  decodeBodyHeader,
  BodyHeader, // eslint-disable-line no-unused-vars
  HeaderInfo // eslint-disable-line no-unused-vars
} from '@aws-crypto/serialize'
import { ParseHeaderStream } from './parse_header_stream'
import { DecipherInfo } from './decipher_stream' // eslint-disable-line no-unused-vars

type AWSVerify = Verify & {awsCryptoVerify: (signature: Buffer) => boolean}
const PortableTransformWithType = (<new (...args: any[]) => Transform>PortableTransform)

export interface VerifyInfo {
  headerInfo: HeaderInfo
  getDecipher: (iv: Uint8Array) => Decipher
  dispose: () => void
  verify?: AWSVerify
}

interface VerifyState {
  buffer: Buffer
  authTagBuffer: Buffer
  currentFrame?: BodyHeader
  signature?: Buffer
}

export class VerifyStream extends PortableTransformWithType {
  private _headerInfo!: HeaderInfo
  private _verifyState: VerifyState = {
    buffer: Buffer.alloc(0),
    authTagBuffer: Buffer.alloc(0)
  }
  private _verify?: AWSVerify
  constructor () {
    super()
    this.on('pipe', (source: ParseHeaderStream) => {
      /* Precondition: The source must emit the required events. */
      needs(source instanceof ParseHeaderStream, 'Unsupported source')
      source.once('VerifyInfo', (verifyInfo: VerifyInfo) => {
        const { getDecipher, verify, headerInfo, dispose } = verifyInfo
        const { messageId, contentType } = headerInfo.messageHeader
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

      if (this._verify) {
        this._verify.update(frameBuffer.slice(0, frameHeader.readPos))
      }
      // clear the buffer.  It _could_ have cipher text...
      state.buffer = Buffer.alloc(0)
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
        state.authTagBuffer = Buffer.concat([authTagBuffer, chunk], tagLengthBytes)
        if (this._verify) {
          this._verify.update(state.authTagBuffer)
        }
        this.emit('AuthTag', state.authTagBuffer)
        const tail = chunk.slice(left)
        if (!currentFrame.isFinalFrame) {
          state.buffer = Buffer.alloc(0)
          state.currentFrame = undefined
          state.authTagBuffer = Buffer.alloc(0)
        }
        return setImmediate(() => this._transform(tail, enc, callback))
      }
    }

    if (chunk.length && state.signature) {
      state.signature = Buffer.concat([state.signature, chunk])
    }

    callback()
  }

  push (chunk: any, encoding?: string | undefined): boolean {
    // Typescript???? this._verify instanceof Verify is better....
    if (this._verify) {
      this._verify.update(chunk)
    }
    return super.push(chunk, encoding)
  }

  _flush (callback: Function) {
    /* Precondition: If there is no verify stream do not attempt to verify. */
    if (!this._verify) return callback()
    /* Precondition: If there is a verify stream, there must be a signature. */
    if (!this._verifyState.signature) throw new Error('Invalid Signature')
    const isVerified = this._verify.awsCryptoVerify(this._verifyState.signature)
    /* Postcondition: The signature must be valid. */
    needs(isVerified, 'Invalid Signature')
    callback()
  }
}
