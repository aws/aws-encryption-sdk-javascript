// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream'
import {
  NodeAlgorithmSuite,
  NodeMaterialsManager,
  getDecryptionHelper,
} from '@aws-crypto/material-management-node'
import { deserializeFactory, kdfInfo } from '@aws-crypto/serialize'
import { VerifyInfo } from './verify_stream'

const toUtf8 = (input: Uint8Array) =>
  Buffer.from(input.buffer, input.byteOffset, input.byteLength).toString('utf8')
const deserialize = deserializeFactory(toUtf8, NodeAlgorithmSuite)
const PortableTransformWithType = PortableTransform as new (
  ...args: any[]
) => Transform

interface HeaderState {
  buffer: Buffer
  headerParsed: boolean
  maxHeaderSize?: number
}

export interface ParseHeaderStreamOptions {
  maxHeaderSize?: number
}

export class ParseHeaderStream extends PortableTransformWithType {
  private materialsManager!: NodeMaterialsManager
  private _headerState: HeaderState
  constructor(
    cmm: NodeMaterialsManager,
    { maxHeaderSize }: ParseHeaderStreamOptions = {}
  ) {
    super()
    Object.defineProperty(this, 'materialsManager', {
      value: cmm,
      enumerable: true,
    })
    this._headerState = {
      buffer: Buffer.alloc(0),
      headerParsed: false,
      maxHeaderSize: maxHeaderSize,
    }
  }

  _transform(chunk: any, encoding: string, callback: Function) {
    const { buffer, maxHeaderSize } = this._headerState
    const headerBuffer = Buffer.concat([buffer, chunk])

    /* We MUST NOT attempt to deserialize
     * more than maxHeaderSize bytes.
     */
    const maxHeaderRead = maxHeaderSize || headerBuffer.byteLength

    /* The intention of this control
     * it to protect against
     * resources with a unexpectedly high bound.
     * Therefore degenerative edge cases
     * where there chunk and the buffer
     * overlap should be avoided.
     * Only "read" the max size.
     */
    const headerInfo = deserialize.deserializeMessageHeader(
      headerBuffer.slice(0, maxHeaderRead)
    )
    if (!headerInfo) {
      /* Precondition: If maxHeaderSize was set I can not buffer a header larger than maxHeaderSize.
       * The header can be up to ~12GB
       * and the entire header MUST be process
       * before it can be determined to be valid.
       * Depending on your requirements this represents
       * an unbounded input.
       * maxHeaderSize is the control to bound this input.
       */
      if (headerBuffer.byteLength > maxHeaderRead)
        return callback(new Error('maxHeaderSize exceeded.'))
      this._headerState.buffer = headerBuffer
      return callback()
    }

    const { messageHeader, algorithmSuite } = headerInfo
    const { rawHeader, headerIv, headerAuthTag } = headerInfo

    const suite = new NodeAlgorithmSuite(algorithmSuite.id)
    const { encryptionContext, encryptedDataKeys } = messageHeader

    this.materialsManager
      .decryptMaterials({ suite, encryptionContext, encryptedDataKeys })
      .then((material) => {
        this._headerState.buffer = Buffer.alloc(0) // clear the Buffer...

        const { kdfGetDecipher, getVerify, dispose } = getDecryptionHelper(
          material
        )

        const info = kdfInfo(messageHeader.suiteId, messageHeader.messageId)
        const getDecipher = kdfGetDecipher(info)
        const headerAuth = getDecipher(headerIv)

        headerAuth.setAAD(
          Buffer.from(
            rawHeader.buffer,
            rawHeader.byteOffset,
            rawHeader.byteLength
          )
        )
        headerAuth.setAuthTag(
          Buffer.from(
            headerAuthTag.buffer,
            headerAuthTag.byteOffset,
            headerAuthTag.byteLength
          )
        )
        headerAuth.update(Buffer.alloc(0))
        headerAuth.final() // will throw if invalid

        const verify = getVerify ? getVerify() : void 0
        const verifyInfo: VerifyInfo = {
          headerInfo,
          getDecipher,
          verify,
          dispose,
        }
        this.emit('VerifyInfo', verifyInfo)
        this.emit('MessageHeader', headerInfo.messageHeader)

        this._headerState.headerParsed = true

        // The header is parsed, pass control
        const readPos =
          rawHeader.byteLength + headerIv.byteLength + headerAuthTag.byteLength
        const tail = headerBuffer.slice(readPos)
        /* needs calls in downstream _transform streams will throw.
         * But streams are async.
         * So this error should be turned into an `.emit('error', ex)`.
         */
        this._transform = (chunk: any, _enc: string, cb: Function) => {
          try {
            cb(null, chunk)
          } catch (ex) {
            this.emit('error', ex)
          }
        }
        // flush the tail.  Stream control is now in the verify and decrypt streams
        return setImmediate(() => this._transform(tail, encoding, callback))
      })
      .catch((err) => callback(err))
  }

  _flush(callback: Function) {
    /* Postcondition: A completed header MUST have been processed.
     * callback is an errBack function,
     * so it expects either an error OR undefined
     */
    callback(
      this._headerState.headerParsed
        ? undefined
        : new Error('Incomplete Header')
    )
  }
}
