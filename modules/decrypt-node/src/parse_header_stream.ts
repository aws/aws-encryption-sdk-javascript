// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream'
import {
  NodeAlgorithmSuite,
  NodeMaterialsManager,
  getDecryptionHelper,
  CommitmentPolicy,
  CommitmentPolicySuites,
  needs,
} from '@aws-crypto/material-management-node'
import { deserializeFactory, MessageHeaderV2 } from '@aws-crypto/serialize'
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
}

export class ParseHeaderStream extends PortableTransformWithType {
  private materialsManager!: NodeMaterialsManager
  private commitmentPolicy!: CommitmentPolicy
  private _headerState: HeaderState
  constructor(commitmentPolicy: CommitmentPolicy, cmm: NodeMaterialsManager) {
    super()

    /* Precondition: ParseHeaderStream needs a valid commitmentPolicy. */
    needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')

    Object.defineProperty(this, 'materialsManager', {
      value: cmm,
      enumerable: true,
    })
    Object.defineProperty(this, 'commitmentPolicy', {
      value: commitmentPolicy,
      enumerable: true,
    })
    this._headerState = {
      buffer: Buffer.alloc(0),
      headerParsed: false,
    }
  }

  _transform(
    chunk: any,
    encoding: string,
    callback: (err?: Error | null, data?: Uint8Array) => void
  ) {
    const { _headerState, commitmentPolicy, materialsManager } = this
    const { buffer } = _headerState
    const headerBuffer = Buffer.concat([buffer, chunk])
    const headerInfo = deserialize.deserializeMessageHeader(headerBuffer)
    if (!headerInfo) {
      _headerState.buffer = headerBuffer
      return callback()
    }

    const { messageHeader, algorithmSuite } = headerInfo
    const messageIDStr = Buffer.from(messageHeader.messageId).toString('hex')
    /* The parsed header algorithmSuite from ParseHeaderStream must be supported by the commitmentPolicy. */
    CommitmentPolicySuites.isDecryptEnabled(
      commitmentPolicy,
      algorithmSuite,
      messageIDStr
    )

    const { rawHeader, headerAuth } = headerInfo
    const { headerIv, headerAuthTag, headerAuthLength } = headerAuth

    const suite = new NodeAlgorithmSuite(algorithmSuite.id)
    const { messageId, encryptionContext, encryptedDataKeys } = messageHeader

    materialsManager
      .decryptMaterials({ suite, encryptionContext, encryptedDataKeys })
      .then((material) => {
        /* The material algorithmSuite returned to ParseHeaderStream must be supported by the commitmentPolicy. */
        CommitmentPolicySuites.isDecryptEnabled(
          commitmentPolicy,
          material.suite,
          messageIDStr
        )

        _headerState.buffer = Buffer.alloc(0) // clear the Buffer...

        const { getDecipherInfo, getVerify, dispose } = getDecryptionHelper(
          material
        )

        const getDecipher = getDecipherInfo(
          messageId,
          /* This is sub-optimal.
           * Ideally I could pluck the `suiteData`
           * right off the header
           * and in such a way that may be undefined.
           * But that has other consequences
           * that are beyond the scope of this course.
           */
          (messageHeader as MessageHeaderV2).suiteData
        )
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

        _headerState.headerParsed = true

        // The header is parsed, pass control
        const readPos = rawHeader.byteLength + headerAuthLength
        const tail = headerBuffer.slice(readPos)
        /* needs calls in downstream _transform streams will throw.
         * But streams are async.
         * So this error should be turned into an `.emit('error', ex)`.
         */
        this._transform = (
          chunk: any,
          _enc: string,
          cb: (err?: Error | null, data?: Uint8Array) => void
        ) => {
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

  _flush(callback: (err?: Error) => void) {
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
