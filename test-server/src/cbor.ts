// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Self-contained CBOR (RFC 8949) codec covering the subset the ESDKTestServer
 * smithy structures need on the wire: maps with text keys, arrays, byte
 * strings, text strings, integers, booleans, floats, and null. The decoder
 * additionally accepts indefinite-length strings/arrays/maps and skips tags,
 * so any conforming rpcv2Cbor client payload decodes.
 */

const MAX_SAFE = Number.MAX_SAFE_INTEGER

export type CborValue =
  | number
  | string
  | boolean
  | null
  | undefined
  | Uint8Array
  | CborValue[]
  | { [key: string]: CborValue }

export function encode(value: CborValue): Buffer {
  const chunks: Buffer[] = []
  encodeItem(value, chunks)
  return Buffer.concat(chunks)
}

function encodeItem(value: CborValue, out: Buffer[]): void {
  if (value === null || value === undefined) {
    out.push(Buffer.from([0xf6]))
  } else if (typeof value === 'boolean') {
    out.push(Buffer.from([value ? 0xf5 : 0xf4]))
  } else if (typeof value === 'number') {
    encodeNumber(value, out)
  } else if (typeof value === 'string') {
    const utf8 = Buffer.from(value, 'utf8')
    encodeHead(3, utf8.length, out)
    out.push(utf8)
  } else if (value instanceof Uint8Array) {
    encodeHead(2, value.length, out)
    out.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength))
  } else if (Array.isArray(value)) {
    encodeHead(4, value.length, out)
    for (const item of value) encodeItem(item, out)
  } else if (typeof value === 'object') {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined)
    encodeHead(5, entries.length, out)
    for (const [k, v] of entries) {
      encodeItem(k, out)
      encodeItem(v, out)
    }
  } else {
    throw new Error(`cannot encode value of type ${typeof value}`)
  }
}

function encodeNumber(value: number, out: Buffer[]): void {
  if (Number.isSafeInteger(value)) {
    if (value >= 0) {
      encodeHead(0, value, out)
    } else {
      encodeHead(1, -value - 1, out)
    }
  } else {
    const buf = Buffer.alloc(9)
    buf[0] = 0xfb
    buf.writeDoubleBE(value, 1)
    out.push(buf)
  }
}

function encodeHead(major: number, length: number, out: Buffer[]): void {
  const mt = major << 5
  if (length < 24) {
    out.push(Buffer.from([mt | length]))
  } else if (length < 0x100) {
    out.push(Buffer.from([mt | 24, length]))
  } else if (length < 0x10000) {
    const buf = Buffer.alloc(3)
    buf[0] = mt | 25
    buf.writeUInt16BE(length, 1)
    out.push(buf)
  } else if (length < 0x100000000) {
    const buf = Buffer.alloc(5)
    buf[0] = mt | 26
    buf.writeUInt32BE(length, 1)
    out.push(buf)
  } else {
    const buf = Buffer.alloc(9)
    buf[0] = mt | 27
    buf.writeBigUInt64BE(BigInt(length), 1)
    out.push(buf)
  }
}

export function decode(bytes: Uint8Array): CborValue {
  const decoder = new Decoder(
    Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  )
  const value = decoder.item()
  if (decoder.pos !== decoder.buf.length) {
    throw new Error(
      `trailing bytes after CBOR item: ${decoder.buf.length - decoder.pos}`
    )
  }
  return value
}

const BREAK = Symbol('cbor-break')

class Decoder {
  pos = 0
  constructor(readonly buf: Buffer) {}

  item(): CborValue {
    const value = this.itemOrBreak()
    if (value === BREAK) throw new Error('unexpected CBOR break code')
    return value
  }

  private itemOrBreak(): CborValue | typeof BREAK {
    const initial = this.u8()
    const major = initial >> 5
    const info = initial & 0x1f
    switch (major) {
      case 0:
        return this.length(info)
      case 1:
        return -1 - this.length(info)
      case 2:
        return this.bytes(info)
      case 3:
        return this.text(info)
      case 4:
        return this.array(info)
      case 5:
        return this.map(info)
      case 6:
        // Tag: skip the tag number, decode the tagged item.
        this.length(info)
        return this.item()
      case 7:
        return this.simple(initial, info)
      default:
        throw new Error(`unsupported CBOR major type: ${major}`)
    }
  }

  private u8(): number {
    if (this.pos >= this.buf.length) throw new Error('truncated CBOR input')
    return this.buf[this.pos++]
  }

  private take(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('truncated CBOR input')
    const slice = this.buf.subarray(this.pos, this.pos + n)
    this.pos += n
    return slice
  }

  /* Argument value for additional info < 24 or the 1/2/4/8-byte forms. */
  private length(info: number): number {
    if (info < 24) return info
    if (info === 24) return this.u8()
    if (info === 25) return this.take(2).readUInt16BE(0)
    if (info === 26) return this.take(4).readUInt32BE(0)
    if (info === 27) {
      const big = this.take(8).readBigUInt64BE(0)
      if (big > BigInt(MAX_SAFE)) {
        throw new Error(`integer out of safe range: ${big}`)
      }
      return Number(big)
    }
    throw new Error(`unsupported CBOR additional info: ${info}`)
  }

  private bytes(info: number): Uint8Array {
    if (info === 31) return Buffer.concat(this.chunks(2) as Buffer[])
    return this.take(this.length(info))
  }

  private text(info: number): string {
    if (info === 31) {
      return (this.chunks(3) as string[]).join('')
    }
    return this.take(this.length(info)).toString('utf8')
  }

  /* Chunk segments of an indefinite-length string (major type 2 or 3). */
  private chunks(major: number): (Buffer | string)[] {
    const parts: (Buffer | string)[] = []
    for (;;) {
      const initial = this.u8()
      if (initial === 0xff) return parts
      if (initial >> 5 !== major) {
        throw new Error('mismatched chunk type in indefinite-length string')
      }
      const info = initial & 0x1f
      parts.push(major === 2 ? this.take(this.length(info)) : this.text(info))
    }
  }

  private array(info: number): CborValue[] {
    const items: CborValue[] = []
    if (info === 31) {
      for (;;) {
        const item = this.itemOrBreak()
        if (item === BREAK) return items
        items.push(item)
      }
    }
    const count = this.length(info)
    for (let i = 0; i < count; i++) items.push(this.item())
    return items
  }

  private map(info: number): { [key: string]: CborValue } {
    const result: { [key: string]: CborValue } = {}
    const entry = () => {
      const key = this.item()
      if (typeof key !== 'string') {
        throw new Error(`non-text CBOR map key: ${typeof key}`)
      }
      result[key] = this.item()
    }
    if (info === 31) {
      for (;;) {
        const initial = this.buf[this.pos]
        if (initial === 0xff) {
          this.pos++
          return result
        }
        entry()
      }
    }
    const count = this.length(info)
    for (let i = 0; i < count; i++) entry()
    return result
  }

  private simple(initial: number, info: number): CborValue | typeof BREAK {
    switch (info) {
      case 20:
        return false
      case 21:
        return true
      case 22:
      case 23:
        return null
      case 25:
        return this.float16()
      case 26:
        return this.take(4).readFloatBE(0)
      case 27:
        return this.take(8).readDoubleBE(0)
      case 31:
        return BREAK
      default:
        throw new Error(
          `unsupported CBOR simple value: 0x${initial.toString(16)}`
        )
    }
  }

  private float16(): number {
    const half = this.take(2).readUInt16BE(0)
    const sign = half & 0x8000 ? -1 : 1
    const exponent = (half >> 10) & 0x1f
    const fraction = half & 0x3ff
    if (exponent === 0) return sign * fraction * 2 ** -24
    if (exponent === 31) return fraction ? NaN : sign * Infinity
    return sign * (1024 + fraction) * 2 ** (exponent - 25)
  }
}
