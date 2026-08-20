// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { expect } from 'chai'
import { decode, encode } from '../src/cbor'

describe('cbor codec', () => {
  it('round-trips the shapes the smithy structures use', () => {
    const value = {
      commitmentPolicy: 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
      maxEncryptedDataKeys: 3,
      negative: -42,
      big: 2 ** 40,
      flag: true,
      cleared: false,
      wrappingKey: Buffer.from([0, 1, 2, 255]),
      childKeyrings: [{ keyName: 'a' }, { keyName: 'b' }],
      encryptionContext: { key: 'value', other: 'entry' },
    }
    const decoded = decode(encode(value)) as { [key: string]: unknown }
    expect(decoded.commitmentPolicy).to.equal('REQUIRE_ENCRYPT_REQUIRE_DECRYPT')
    expect(decoded.maxEncryptedDataKeys).to.equal(3)
    expect(decoded.negative).to.equal(-42)
    expect(decoded.big).to.equal(2 ** 40)
    expect(decoded.flag).to.equal(true)
    expect(decoded.cleared).to.equal(false)
    expect(Buffer.from(decoded.wrappingKey as Uint8Array)).to.deep.equal(
      Buffer.from([0, 1, 2, 255])
    )
    expect(decoded.childKeyrings).to.deep.equal([
      { keyName: 'a' },
      { keyName: 'b' },
    ])
    expect(decoded.encryptionContext).to.deep.equal({
      key: 'value',
      other: 'entry',
    })
  })

  it('omits undefined map members', () => {
    const decoded = decode(encode({ present: 1, absent: undefined })) as {
      [key: string]: unknown
    }
    expect(Object.keys(decoded)).to.deep.equal(['present'])
  })

  it('encodes null as CBOR null', () => {
    expect(encode(null)).to.deep.equal(Buffer.from([0xf6]))
    expect(decode(Buffer.from([0xf6]))).to.equal(null)
  })

  it('decodes indefinite-length maps, arrays, and strings', () => {
    // {_ "a": [_ 1, 2], "b": (_ h'01', h'02'), "c": (_ "he", "llo")}
    const bytes = Buffer.from([
      0xbf, // map, indefinite
      0x61,
      0x61, // "a"
      0x9f,
      0x01,
      0x02,
      0xff, // [_ 1, 2]
      0x61,
      0x62, // "b"
      0x5f,
      0x41,
      0x01,
      0x41,
      0x02,
      0xff, // (_ h'01', h'02')
      0x61,
      0x63, // "c"
      0x7f,
      0x62,
      0x68,
      0x65,
      0x63,
      0x6c,
      0x6c,
      0x6f,
      0xff, // (_ "he", "llo")
      0xff, // break
    ])
    const decoded = decode(bytes) as { [key: string]: unknown }
    expect(decoded.a).to.deep.equal([1, 2])
    expect(Buffer.from(decoded.b as Uint8Array)).to.deep.equal(
      Buffer.from([1, 2])
    )
    expect(decoded.c).to.equal('hello')
  })

  it('decodes tagged items by skipping the tag', () => {
    // 1(1363896240) — tag 1 (epoch time) around a uint
    const bytes = Buffer.from([0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0])
    expect(decode(bytes)).to.equal(1363896240)
  })

  it('decodes 64-bit lengths and floats', () => {
    // 27-form uint holding 2^40
    const big = Buffer.from([
      0x1b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    expect(decode(big)).to.equal(2 ** 40)
    // float64 1.5
    const f64 = Buffer.from([
      0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ])
    expect(decode(f64)).to.equal(1.5)
  })

  it('rejects unsafe 64-bit integers', () => {
    const bytes = Buffer.from([
      0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ])
    expect(() => decode(bytes)).to.throw('out of safe range')
  })

  it('rejects trailing bytes', () => {
    expect(() => decode(Buffer.from([0x01, 0x02]))).to.throw('trailing bytes')
  })

  it('rejects truncated input', () => {
    expect(() => decode(Buffer.from([0x62, 0x68]))).to.throw('truncated')
  })
})
