// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { needs } from '@aws-crypto/material-management'

const UINT8_OVERFLOW = 2 ** 8
export function uInt8(number: number) {
  /* Precondition: Number must be 0-(2^8 - 1). */
  needs(number < UINT8_OVERFLOW && number >= 0, 'number out of bounds.')

  const buff = new Uint8Array(1)
  const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength)
  view.setUint8(0, number)
  return buff
}

const UINT16__OVERFLOW = 2 ** 16
export function uInt16BE(number: number) {
  /* Precondition: Number must be 0-(2^16 - 1). */
  needs(number < UINT16__OVERFLOW && number >= 0, 'number out of bounds.')

  const buff = new Uint8Array(2)
  const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength)
  view.setUint16(0, number, false) // big-endian
  return buff
}

const UINT32__OVERFLOW = 2 ** 32
export function uInt32BE(number: number) {
  /* Precondition: Number must be 0-(2^32 - 1). */
  needs(number < UINT32__OVERFLOW && number >= 0, 'number out of bounds.')

  const buff = new Uint8Array(4)
  const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength)
  view.setUint32(0, number, false) // big-endian
  return buff
}
