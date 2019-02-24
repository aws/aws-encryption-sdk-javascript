
export function uInt8(number:number) {
  const buff = new Uint8Array(1)
  const view = new DataView(buff.buffer)
  view.setUint8(0, number)
  return buff
}

export function uInt16BE(number: number) {
  const buff = new Uint8Array(2)
  const view = new DataView(buff.buffer)
  view.setUint16(0, number, false) // big-endian
  return buff
}

export function uInt32BE(number: number) {
  const buff = new Uint8Array(4)
  const view = new DataView(buff.buffer)
  view.setUint32(0, number, false) // big-endian
  return buff
}
