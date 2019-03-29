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

import { needs } from '@aws-crypto/material-management'

const UINT8_OVERFLOW = 2 ** 8
export function uInt8 (number:number) {
  /* Precondition: Number must be 0-(2^8 - 1). */
  needs(number < UINT8_OVERFLOW && number >= 0, 'number out of bounds.')

  const buff = new Uint8Array(1)
  const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength)
  view.setUint8(0, number)
  return buff
}

const UINT16__OVERFLOW = 2 ** 16
export function uInt16BE (number: number) {
  /* Precondition: Number must be 0-(2^16 - 1). */
  needs(number < UINT16__OVERFLOW && number >= 0, 'number out of bounds.')

  const buff = new Uint8Array(2)
  const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength)
  view.setUint16(0, number, false) // big-endian
  return buff
}

const UINT32__OVERFLOW = 2 ** 32
export function uInt32BE (number: number) {
  /* Precondition: Number must be 0-(2^32 - 1). */
  needs(number < UINT32__OVERFLOW && number >= 0, 'number out of bounds.')

  const buff = new Uint8Array(4)
  const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength)
  view.setUint32(0, number, false) // big-endian
  return buff
}
