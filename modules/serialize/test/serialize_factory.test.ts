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

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import { serializeFactory } from '../src/serialize_factory'
import { SerializationVersion, ContentType, ObjectType } from '../src/identifiers'
import * as fixtures from './fixtures'

describe('serializeFactory:frameIv', () => {
  it('should return a rational IV', () => {
    const fromUtf8 = () => { throw new Error('not used') }
    const { frameIv } = serializeFactory(fromUtf8)
    const test = frameIv(12, 1)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(12)
    expect(test).to.deep.equal(fixtures.basicFrameIV())
  })

  it('Precondition: sequenceNumber must conform to the specification. i.e. 0 - (2^32 - 1)', () => {
    const fromUtf8 = () => { throw new Error('not used') }
    const { frameIv } = serializeFactory(fromUtf8)
    expect(() => frameIv(12, 0)).to.throw()
  })
})

describe('serializeFactory:nonFramedBodyIv', () => {
  it('should return a rational IV', () => {
    const fromUtf8 = () => { throw new Error('not used') }
    const { nonFramedBodyIv } = serializeFactory(fromUtf8)
    const test = nonFramedBodyIv(12)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(12)
    expect(test).to.deep.equal(fixtures.basicNonFrameIV())
  })
})

describe('serializeFactory:headerAuthIv', () => {
  it('should return a rational IV', () => {
    const fromUtf8 = () => { throw new Error('not used') }
    const { headerAuthIv } = serializeFactory(fromUtf8)
    const test = headerAuthIv(12)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(12)
    expect(test).to.deep.equal(fixtures.headerAuthIV())
  })
})

describe('serializeFactory:frameHeader', () => {
  it('should return a rational frameHeader', () => {
    const fromUtf8 = () => { throw new Error('not used') }
    const { frameHeader, frameIv } = serializeFactory(fromUtf8)
    const sequenceNumber = 1
    const iv = frameIv(12, sequenceNumber)
    const test = frameHeader(sequenceNumber, iv)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(16)
    expect(test).to.deep.equal(fixtures.basicFrameHeader())
  })
})

describe('serializeFactory:finalFrameHeader', () => {
  it('should return a rational finalFrameHeader', () => {
    const fromUtf8 = () => { throw new Error('not used') }
    const { finalFrameHeader, frameIv } = serializeFactory(fromUtf8)
    const sequenceNumber = 1
    const iv = frameIv(12, sequenceNumber)
    const test = finalFrameHeader(sequenceNumber, iv, 999)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(24)
    expect(test).to.deep.equal(fixtures.finalFrameHeader())
  })
})

describe('serializeFactory:encodeEncryptionContext', () => {
  it('should return rational byte array', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { encodeEncryptionContext } = serializeFactory(fromUtf8)
    const test = encodeEncryptionContext({ information: '\u00bd + \u00bc = \u00be', some: 'public' })
    expect(test).to.be.instanceof(Array)
    expect(test.length).to.eql(2)
    expect(test[0]).to.be.instanceof(Uint8Array)
    expect(test[1]).to.be.instanceof(Uint8Array)
    expect(test[0]).to.deep.equal(new Uint8Array([ 0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190 ]))
    expect(test[1]).to.deep.equal(new Uint8Array([ 0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99 ]))
  })

  it('should sort by key', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { encodeEncryptionContext } = serializeFactory(fromUtf8)
    const test = encodeEncryptionContext({ some: 'public', information: '\u00bd + \u00bc = \u00be' })
    expect(test[0]).to.deep.equal(new Uint8Array([ 0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190 ]))
    expect(test[1]).to.deep.equal(new Uint8Array([ 0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99 ]))
  })
})

describe('serializeFactory:serializeEncryptionContext', () => {
  it('should return rational context bytes', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { encodeEncryptionContext, serializeEncryptionContext } = serializeFactory(fromUtf8)
    const contextBytes = encodeEncryptionContext({ some: 'public', information: '\u00bd + \u00bc = \u00be' })
    const test = serializeEncryptionContext(contextBytes)

    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(45)
    expect(test).to.deep.equal(fixtures.basicEncryptionContext())
  })

  it('Precondition: If there is no context then the length of the _whole_ serialized portion is 00.', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { encodeEncryptionContext, serializeEncryptionContext } = serializeFactory(fromUtf8)
    const contextBytes = encodeEncryptionContext({})
    const test = serializeEncryptionContext(contextBytes)

    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(2)
  })
})

describe('serializeFactory:serializeEncryptedDataKeys', () => {
  it('should return a rational data key section', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { serializeEncryptedDataKeys } = serializeFactory(fromUtf8)
    const test = serializeEncryptedDataKeys([
      { providerInfo: 'firstKey', providerId: '\u00bd + \u00bc = \u00be', encryptedDataKey: new Uint8Array([1, 2, 3, 4, 5]) },
      { providerInfo: 'secondKey', providerId: '\u00bd + \u00bc = \u00be', encryptedDataKey: new Uint8Array([6, 7, 8, 9, 0]) }
    ])

    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(65)
    expect(test).to.deep.equal(fixtures.encryptedDataKey())
  })
})

describe('serializeFactory:serializeMessageHeader', () => {
  it('should return a rational raw header', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { serializeMessageHeader } = serializeFactory(fromUtf8)
    const test = serializeMessageHeader({
      version: SerializationVersion.V1,
      type: ObjectType.CUSTOMER_AE_DATA,
      suiteId: 0x0014,
      messageId: new Uint8Array([ 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 ]),
      encryptionContext: { some: 'public', information: '\u00bd + \u00bc = \u00be' },
      encryptedDataKeys: [
        { providerInfo: 'firstKey', providerId: '\u00bd + \u00bc = \u00be', encryptedDataKey: new Uint8Array([1, 2, 3, 4, 5]) },
        { providerInfo: 'secondKey', providerId: '\u00bd + \u00bc = \u00be', encryptedDataKey: new Uint8Array([6, 7, 8, 9, 0]) }
      ],
      contentType: ContentType.FRAMED_DATA,
      headerIvLength: 12,
      frameLength: 4096
    })

    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(140)
    expect(test).to.deep.equal(fixtures.basicMessageHeader())
  })

  it('should return a header with 0,0 for context length and _not_ 0,0 for element count', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { serializeMessageHeader } = serializeFactory(fromUtf8)
    const test = serializeMessageHeader({
      version: SerializationVersion.V1,
      type: ObjectType.CUSTOMER_AE_DATA,
      suiteId: 0x0014,
      messageId: new Uint8Array([ 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 ]),
      encryptionContext: {},
      encryptedDataKeys: [
        { providerInfo: 'firstKey', providerId: '\u00bd + \u00bc = \u00be', encryptedDataKey: new Uint8Array([1, 2, 3, 4, 5]) },
        { providerInfo: 'secondKey', providerId: '\u00bd + \u00bc = \u00be', encryptedDataKey: new Uint8Array([6, 7, 8, 9, 0]) }
      ],
      contentType: ContentType.FRAMED_DATA,
      headerIvLength: 12,
      frameLength: 4096
    })

    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(97)
    expect(test).to.deep.equal(fixtures.zeroByteEncryptionContextMessageHeader())
  })
})
