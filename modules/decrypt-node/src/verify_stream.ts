// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream'
import {
  needs,
  GetVerify,
  GetDecipher,
} from '@aws-crypto/material-management-node'
import {
  deserializeSignature,
  decodeBodyHeader,
  BodyHeader,
  HeaderInfo,
  serializeMessageHeaderAuth,
} from '@aws-crypto/serialize'
import { ParseHeaderStream } from './parse_header_stream'
import { DecipherInfo } from './decipher_stream'

type AWSVerify = ReturnType<GetVerify>
const PortableTransformWithType = PortableTransform as new (
  ...args: any[]
) => Transform

export interface VerifyInfo {
  headerInfo: HeaderInfo
  getDecipher: GetDecipher
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
  sequenceNumber: number
  finalAuthTagReceived: boolean
}

export class VerifyStream extends PortableTransformWithType {
  private _headerInfo!: HeaderInfo
  private _verifyState: VerifyState = {
    buffer: Buffer.alloc(0),
    authTagBuffer: Buffer.alloc(0),
    signatureInfo: Buffer.alloc(0),
    sequenceNumber: 0,
    finalAuthTagReceived: false,
  }
  private _verify?: AWSVerify
  private _maxBodySize?: number
  constructor({ maxBodySize }: VerifyStreamOptions) {
    super()
    /* Precondition: VerifyStream requires maxBodySize must be falsey or a number. */
    needs(
      !maxBodySize || typeof maxBodySize === 'number',
      'Unsupported MaxBodySize.'
    )
    Object.defineProperty(this, '_maxBodySize', {
      value: maxBodySize,
      enumerable: true,
    })

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
          const { rawHeader, headerAuth, messageHeader } = headerInfo
          const { headerIv, headerAuthTag } = headerAuth
          verify.update(rawHeader)
          verify.update(
            serializeMessageHeaderAuth({
              headerIv,
              headerAuthTag,
              messageHeader,
            })
          )
        }
        Object.defineProperty(this, '_headerInfo', {
          value: headerInfo,
          enumerable: true,
        })
        Object.defineProperty(this, '_verify', {
          value: verify,
          enumerable: true,
        })

        const decipherInfo: DecipherInfo = {
          messageId: Buffer.from(
            (messageId as Uint8Array).buffer || messageId,
            (messageId as Uint8Array).byteOffset || 0,
            messageId.byteLength
          ),
          contentType,
          getDecipher,
          dispose,
        }
        this.emit('DecipherInfo', decipherInfo)
      })
    })
  }

  _transform(
    chunk: Buffer,
    enc: string,
    callback: (err?: Error | null, data?: Uint8Array) => void
  ): any {
    /* Precondition: VerifyInfo must have initialized the stream. */
    needs(
      this._headerInfo,
      'VerifyStream not configured, VerifyInfo event not yet received.'
    )

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
      needs(
        !this._maxBodySize || this._maxBodySize >= frameHeader.contentLength,
        'maxBodySize exceeded.'
      )

      /* Keeping track of the sequence number myself. */
      state.sequenceNumber += 1

      /* Precondition: The sequence number is required to monotonically increase, starting from 1.
       * This is to avoid a bad actor from abusing the sequence number on un-signed algorithm suites.
       * If the frame size matched the data format (say NDJSON),
       * then the data could be significantly altered just by rearranging the frames.
       * Non-framed data returns a sequenceNumber of 1.
       */
      needs(
        frameHeader.sequenceNumber === state.sequenceNumber,
        'Encrypted body sequence out of order.'
      )

      if (this._verify) {
        this._verify.update(frameBuffer.slice(0, frameHeader.readPos))
      }
      const tail = frameBuffer.slice(frameHeader.readPos)
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
        const finalAuthTagBuffer = Buffer.concat(
          [authTagBuffer, chunk],
          tagLengthBytes
        )
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
          /* Signal that the we are at the end of the ciphertext.
           * See decodeBodyHeader, non-framed will set isFinalFrame
           * for the single frame.
           */
          this._verifyState.finalAuthTagReceived = true
          /* Overwriting the _transform function.
           * Data flow control is now handled here.
           */
          this._transform = (
            chunk: Buffer,
            _enc: string,
            callback: (err?: Error | null, data?: Uint8Array) => void
          ) => {
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

  push(chunk: any, encoding?: BufferEncoding): boolean {
    // Typescript???? this._verify instanceof Verify is better....
    if (this._verify && chunk) {
      this._verify.update(chunk)
    }
    return super.push(chunk, encoding)
  }

  _flush(callback: (err?: Error) => void) {
    const { finalAuthTagReceived } = this._verifyState
    /* Precondition: All ciphertext MUST have been received.
     * The verify stream has ended,
     * there will be no more data.
     * Therefore we MUST have reached the end.
     */
    if (!finalAuthTagReceived) return callback(new Error('Incomplete message'))
    /* Check for early return (Postcondition): If there is no verify stream do not attempt to verify. */
    if (!this._verify) return callback()
    try {
      const { signatureInfo } = this._verifyState
      /* Precondition: The signature must be well formed. */
      const { buffer, byteOffset, byteLength } =
        deserializeSignature(signatureInfo)
      const signature = Buffer.from(buffer, byteOffset, byteLength)
      const isVerified = this._verify.awsCryptoVerify(signature)
      /* Postcondition: The signature must be valid. */
      needs(isVerified, 'Invalid Signature')
      callback()
    } catch (e) {
      callback(e)
    }
  }
}
