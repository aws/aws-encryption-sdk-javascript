import {BinaryData} from './types'

export function concatBuffers(...inputBuffers: (BinaryData|SharedArrayBuffer|ArrayBufferView)[]) {
  const neededLength = inputBuffers.reduce((sum, buff) => sum += buff.byteLength, 0)
  const outputBuffer = new Uint8Array(neededLength)
  let offset = 0

  inputBuffers
    .forEach(buff => {
      if (buff instanceof ArrayBuffer) {
        outputBuffer.set(new Uint8Array(buff), offset)
      } else if (buff instanceof DataView) {
        outputBuffer.set(new Uint8Array(buff.buffer), offset)
      } else {
        // @ts-ignore What type is the "without length?"
        outputBuffer.set(buff, offset)
      }
      offset += buff.byteLength
    })

  return outputBuffer
}
