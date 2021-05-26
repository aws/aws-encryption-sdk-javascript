// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream'
import {
  needs,
  GetDecipher,
  AwsEsdkJsDecipherGCM,
} from '@aws-crypto/material-management-node'
import { aadFactory, ContentType } from '@aws-crypto/serialize'
import { VerifyStream } from './verify_stream'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const aadUtility = aadFactory(fromUtf8)
const PortableTransformWithType = PortableTransform as new (
  ...args: any[]
) => Transform

export interface DecipherInfo {
  messageId: Buffer
  contentType: ContentType
  getDecipher: GetDecipher
  dispose: () => void
}

interface DecipherState {
  decipher: AwsEsdkJsDecipherGCM
  content: Buffer[]
  contentLength: number
}

export interface BodyInfo {
  iv: Buffer
  contentLength: number
  sequenceNumber: number
  isFinalFrame: boolean
}

const ioTick = async () => new Promise((resolve) => setImmediate(resolve))
const noop = () => {} // eslint-disable-line @typescript-eslint/no-empty-function

export function getDecipherStream() {
  let decipherInfo: DecipherInfo
  let decipherState: DecipherState = {} as any
  let pathologicalDrain: (reason?: any) => void = noop
  let frameComplete: ((err?: Error) => void) | false = false

  return new (class DecipherStream extends PortableTransformWithType {
    constructor() {
      super()
      this.on('pipe', (source: VerifyStream) => {
        /* Precondition: The source must be a VerifyStream to emit the required events. */
        needs(source instanceof VerifyStream, 'Unsupported source')
        source
          .once('DecipherInfo', (info: DecipherInfo) => {
            decipherInfo = info
          })
          .on('BodyInfo', this._onBodyHeader)
          .on('AuthTag', (authTag: Buffer, next: (err?: Error) => void) => {
            this._onAuthTag(authTag, next).catch((e) => this.emit('error', e))
          })
      })
    }

    _onBodyHeader = ({
      iv,
      contentLength,
      sequenceNumber,
      isFinalFrame,
    }: BodyInfo) => {
      /* Precondition: decipherInfo must be set before BodyInfo is sent. */
      needs(decipherInfo, 'Malformed State.')
      /* Precondition: Ciphertext must not be flowing before a BodyHeader is processed. */
      needs(!decipherState.decipher, 'Malformed State.')

      const { messageId, contentType, getDecipher } = decipherInfo
      const aadString = aadUtility.messageAADContentString({
        contentType,
        isFinalFrame,
      })
      const messageAAD = aadUtility.messageAAD(
        messageId,
        aadString,
        sequenceNumber,
        contentLength
      )
      const decipher = getDecipher(iv).setAAD(
        Buffer.from(
          messageAAD.buffer,
          messageAAD.byteOffset,
          messageAAD.byteLength
        )
      )
      const content: Buffer[] = []
      decipherState = { decipher, content, contentLength }
    }

    _transform(chunk: any, _encoding: string, callback: (err?: Error) => void) {
      /* Precondition: BodyHeader must be parsed before frame data. */
      needs(decipherState.decipher, 'Malformed State.')

      decipherState.contentLength -= chunk.length
      /* Precondition: Only content should be transformed, so the lengths must always match.
       * The BodyHeader and AuthTag are striped in the VerifyStream and passed in
       * through events.  This means that if I receive a chunk without having reset
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

    _read(size: number) {
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

    _onAuthTag = async (authTag: Buffer, next: (err?: Error) => void) => {
      const { decipher, content, contentLength } = decipherState
      /* Precondition: _onAuthTag must be called only after a frame has been accumulated.
       * However there is an edge case.  The final frame _can_ be zero length.
       * This means that _transform will never be called.
       */
      needs(frameComplete || contentLength === 0, 'AuthTag before frame.')
      /* Precondition UNTESTED: I must have received all content for this frame.
       * Both contentLength and frameComplete are private variables.
       * As such manipulating them separately outside of the _transform function
       * should not be possible.
       * I do not know of this condition would ever be false while the above is true.
       * But I do not want to remove the check as there may be a more complicated case
       * that makes this possible.
       * If such a case is found.
       * Write a test.
       */
      needs(contentLength === 0, 'Lengths do not match')

      // flush content from state.
      decipherState = {} as any

      decipher.setAuthTag(authTag)
      /* In Node.js versions 10.9 and older will fail to decrypt if decipher.update is not called.
       * https://github.com/nodejs/node/pull/22538 fixes this.
       */
      if (!content.length) decipher.update(Buffer.alloc(0))

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
          await new Promise((resolve) => {
            pathologicalDrain = resolve
          })
        }
      }

      /* This frame is complete.
       * Need to notify the VerifyStream continue.
       * See the note in `AuthTag` for details.
       * The short answer is that for small frame sizes,
       * the "next" frame associated auth tag may be
       * parsed and send before the "current" is processed.
       * This will cause the auth tag event to fire before
       * any _transform events fire and a 'Lengths do not match' precondition to fail.
       */
      next()

      // This frame is complete. Notify _transform to continue, see needs above for more details
      if (frameComplete) frameComplete()
      // reset for next frame.
      frameComplete = false
    }

    _destroy() {
      // It is possible to have to destroy the stream before
      // decipherInfo is set.  Especially if the HeaderAuth
      // is not valid.
      decipherInfo && decipherInfo.dispose()
    }
  })()
}
