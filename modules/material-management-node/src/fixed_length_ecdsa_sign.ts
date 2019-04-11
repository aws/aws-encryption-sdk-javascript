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

import {
  Hash, // eslint-disable-line no-unused-vars
  BinaryLike // eslint-disable-line no-unused-vars
} from 'crypto'
// @ts-ignore
import { Transform as PortableTransform } from 'readable-stream'
import { Transform } from 'stream' // eslint-disable-line no-unused-vars
import {
  supported,
  NodeECDSACurve // eslint-disable-line no-unused-vars
} from './supported_ecdsa_curves'
const PortableTransformWithType = (<new (...args: any[]) => Transform>PortableTransform)

export function createFixedLengthECDHSign (curve: NodeECDSACurve) {
  if (!supported[curve]) throw new Error(`${curve} not supported.`)
  return new FixedLengthECDSASign(curve)
}

export class FixedLengthECDSASign extends PortableTransformWithType {
  _hash: Hash
  sign: (pem: string) => Buffer
  constructor (curve: NodeECDSACurve) {
    super()
    if (!supported[curve]) throw new Error(`${curve} not supported.`)
    const { _hash, sign } = supported[curve]()
    this._hash = _hash
    this.sign = sign
  }

  _transform (chunk: BinaryLike, _encoding: string, callback: Function) {
    this._hash.update(chunk)
    callback(chunk)
  }

  update (data:BinaryLike) {
    this._hash.update(data)
    return this
  }
}
