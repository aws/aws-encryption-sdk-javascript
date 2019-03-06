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

import { Transform } from 'stream'
import { Signer } from 'crypto' // eslint-disable-line no-unused-vars

type GetSigner = () => Signer
export class SignatureStream extends Transform {
  private _signer!: Signer|undefined
  constructor (getSigner?: GetSigner) {
    super()
    const value = getSigner && getSigner()
    Object.defineProperty(this, '_signer', { value, enumerable: true })
  }

  _transform (chunk: any, _encoding: string, callback: Function) {
    // If we have a signer, push the data to it
    this._signer && this._signer.update(chunk)
    // forward the data on
    callback(null, chunk)
  }

  _flush (callback: Function) {
    // @ts-ignore The private key is already bound. Emit the signature
    this._signer && this.push(this._signer.sign())
    callback()
  }
}
