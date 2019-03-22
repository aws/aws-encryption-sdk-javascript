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

import { BinaryData } from './types' // eslint-disable-line no-unused-vars



export function concatBuffers (...inputBuffers: (BinaryData|ArrayBufferView)[]) {
  const neededLength = inputBuffers.reduce((sum, buff) => sum + buff.byteLength, 0)
  const outputBuffer = new Uint8Array(neededLength)
  let offset = 0

  inputBuffers
    .forEach(buff => {
      if (ArrayBuffer.isView(buff)) {
        const {buffer, byteOffset, byteLength} = buff
        outputBuffer.set(new Uint8Array(buffer, byteOffset, byteLength), offset)
      } else {
        outputBuffer.set(new Uint8Array(buff), offset)
      }
      offset += buff.byteLength
    })

  return outputBuffer
}
