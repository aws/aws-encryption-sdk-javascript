/**
 *
 * The encryption SDK stores elements in the form of length data.
 * e.g. 4data.  The length element is Uint16 Big Endian.
 * So knowing the number of elements of this form I can
 * advance through a buffer.  The rub comes when streaming
 * data.  The I may know the number of elements, but not
 * yet have all the data.  In this case I check the lengths and
 * return false.
 *
 * @param elementCount
 * @param buffer 
 * @param readPos
 */

export function readElements(elementCount: number, buffer: Uint8Array, readPos: number = 0) {
  const dataView = new DataView(buffer.buffer)
  const elements = []

  while (elementCount--) {
    if (readPos + 2 > dataView.byteLength) return false
    const length = dataView.getUint16(readPos, false)
    readPos += 2
    if (readPos + length > dataView.byteLength) return false
    const elementBinary = buffer.slice(readPos, readPos + length)
    elements.push(elementBinary)
    readPos += length
  }
  return {elements, readPos}
}
