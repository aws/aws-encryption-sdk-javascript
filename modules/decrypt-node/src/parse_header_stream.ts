// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream' // eslint-disable-line no-unused-vars
import {
  NodeAlgorithmSuite,
  NodeMaterialsManager, // eslint-disable-line no-unused-vars
  getDecryptionHelper
} from '@aws-crypto/material-management-node'
import { deserializeFactory, kdfInfo } from '@aws-crypto/serialize'
import { VerifyInfo } from './verify_stream' // eslint-disable-line no-unused-vars

const toUtf8 = (input: Uint8Array) => Buffer
  .from(input.buffer, input.byteOffset, input.byteLength)
  .toString('utf8')
const deserialize = deserializeFactory(toUtf8, NodeAlgorithmSuite)
const PortableTransformWithType = (<new (...args: any[]) => Transform>PortableTransform)

interface HeaderState {
  buffer: Buffer
}

export class ParseHeaderStream extends PortableTransformWithType {
  private materialsManager!: NodeMaterialsManager
  private _headerState: HeaderState
  constructor (cmm: NodeMaterialsManager) {
    super()
    Object.defineProperty(this, 'materialsManager', { value: cmm, enumerable: true })
    this._headerState = {
      buffer: Buffer.alloc(0)
    }
  }

  _transform (chunk: any, encoding: string, callback: Function) {
    const { buffer } = this._headerState
    const headerBuffer = Buffer.concat([buffer, chunk])
    const headerInfo = deserialize.deserializeMessageHeader(headerBuffer)
    if (!headerInfo) {
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

        const { kdfGetDecipher, getVerify, dispose } = getDecryptionHelper(material)

        const info = kdfInfo(messageHeader.suiteId, messageHeader.messageId)
        const getDecipher = kdfGetDecipher(info)
        const headerAuth = getDecipher(headerIv)

        headerAuth.setAAD(Buffer.from(rawHeader.buffer, rawHeader.byteOffset, rawHeader.byteLength))
        headerAuth.setAuthTag(Buffer.from(headerAuthTag.buffer, headerAuthTag.byteOffset, headerAuthTag.byteLength))
        headerAuth.update(Buffer.alloc(0))
        headerAuth.final() // will throw if invalid

        const verify = getVerify ? getVerify() : void 0
        const verifyInfo: VerifyInfo = { headerInfo, getDecipher, verify, dispose }
        this.emit('VerifyInfo', verifyInfo)
        this.emit('MessageHeader', headerInfo.messageHeader)

        // The header is parsed, pass control
        const readPos = rawHeader.byteLength + headerIv.byteLength + headerAuthTag.byteLength
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
      .catch(err => callback(err))
  }
}
