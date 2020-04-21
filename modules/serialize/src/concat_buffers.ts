// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { BinaryData } from './types'

export function concatBuffers(
  ...inputBuffers: (BinaryData | ArrayBufferView)[]
) {
  const neededLength = inputBuffers.reduce(
    (sum, buff) => sum + buff.byteLength,
    0
  )
  const outputBuffer = new Uint8Array(neededLength)
  let offset = 0

  inputBuffers.forEach((buff) => {
    if (ArrayBuffer.isView(buff)) {
      const { buffer, byteOffset, byteLength } = buff
      outputBuffer.set(new Uint8Array(buffer, byteOffset, byteLength), offset)
    } else {
      outputBuffer.set(new Uint8Array(buff), offset)
    }
    offset += buff.byteLength
  })

  return outputBuffer
}
