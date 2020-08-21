// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Transform } from 'stream'
import { GetSigner } from '@aws-crypto/material-management-node'
import { serializeSignatureInfo } from '@aws-crypto/serialize'

type AWSSigner = ReturnType<GetSigner>

export class SignatureStream extends Transform {
  private _signer!: AWSSigner | undefined
  constructor(getSigner?: GetSigner) {
    super()
    const value = getSigner && getSigner()
    Object.defineProperty(this, '_signer', { value, enumerable: true })
  }

  _transform(
    chunk: any,
    _encoding: string,
    callback: (err?: Error | null, data?: Uint8Array) => void
  ) {
    // If we have a signer, push the data to it
    this._signer && this._signer.update(chunk)
    // forward the data on
    callback(null, chunk)
  }

  _flush(callback: (err?: Error) => void) {
    if (this._signer) {
      const signature = this._signer.awsCryptoSign()
      this.push(serializeSignatureInfo(signature))
    }
    callback()
  }
}
