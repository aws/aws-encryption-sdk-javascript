// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  serializeFactory,
  serializeMessageHeaderAuth,
} from '../src/serialize_factory'
import {
  SerializationVersion,
  ContentType,
  ObjectType,
} from '../src/identifiers'
import * as fixtures from './fixtures'
import { MessageHeaderV1, MessageHeaderV2 } from '../src'

describe('serializeFactory:frameIv', () => {
  it('should return a rational IV', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
    const { frameIv } = serializeFactory(fromUtf8)
    const test = frameIv(12, 1)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(12)
    expect(test).to.deep.equal(fixtures.basicFrameIV())
  })

  it('Precondition: sequenceNumber must conform to the specification. i.e. 1 - (2^32 - 1)', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
    const { frameIv } = serializeFactory(fromUtf8)
    expect(() => frameIv(12, 0)).to.throw()
  })
})

describe('serializeFactory:nonFramedBodyIv', () => {
  it('should return a rational IV', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
    const { nonFramedBodyIv } = serializeFactory(fromUtf8)
    const test = nonFramedBodyIv(12)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(12)
    expect(test).to.deep.equal(fixtures.basicNonFrameIV())
  })
})

describe('serializeFactory:headerAuthIv', () => {
  it('should return a rational IV', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
    const { headerAuthIv } = serializeFactory(fromUtf8)
    const test = headerAuthIv(12)
    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(12)
    expect(test).to.deep.equal(fixtures.headerAuthIV())
  })
})

describe('serializeFactory:frameHeader', () => {
  it('should return a rational frameHeader', () => {
    const fromUtf8 = () => {
      throw new Error('not used')
    }
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
    const fromUtf8 = () => {
      throw new Error('not used')
    }
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
    const test = encodeEncryptionContext({
      information: '\u00bd + \u00bc = \u00be',
      some: 'public',
    })
    expect(test).to.be.instanceof(Array)
    expect(test.length).to.eql(2)
    expect(test[0]).to.be.instanceof(Uint8Array)
    expect(test[1]).to.be.instanceof(Uint8Array)
    expect(test[0]).to.deep.equal(
      new Uint8Array([
        0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194,
        189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190,
      ])
    )
    expect(test[1]).to.deep.equal(
      new Uint8Array([
        0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99,
      ])
    )
  })

  it('Precondition: The serialized encryption context entries must be sorted by UTF-8 key value.', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { encodeEncryptionContext } = serializeFactory(fromUtf8)
    const test = encodeEncryptionContext({
      some: 'public',
      information: '\u00bd + \u00bc = \u00be',
    })
    expect(test[0]).to.deep.equal(
      new Uint8Array([
        0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194,
        189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190,
      ])
    )
    expect(test[1]).to.deep.equal(
      new Uint8Array([
        0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99,
      ])
    )
  })
})

describe('serializeFactory:serializeEncryptionContext', () => {
  it('should return rational context bytes', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { serializeEncryptionContext } = serializeFactory(fromUtf8)
    const test = serializeEncryptionContext({
      some: 'public',
      information: '\u00bd + \u00bc = \u00be',
    })

    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(45)
    expect(test).to.deep.equal(fixtures.basicEncryptionContext())
  })

  it('Check for early return (Postcondition): If there is no context then the length of the _whole_ serialized portion is 0.', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { serializeEncryptionContext } = serializeFactory(fromUtf8)
    const test = serializeEncryptionContext({})

    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(2)
  })
})

describe('serializeFactory:serializeEncryptedDataKeys', () => {
  it('should return a rational data key section', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { serializeEncryptedDataKeys } = serializeFactory(fromUtf8)
    const test = serializeEncryptedDataKeys([
      {
        providerInfo: 'firstKey',
        providerId: '\u00bd + \u00bc = \u00be',
        encryptedDataKey: new Uint8Array([1, 2, 3, 4, 5]),
      },
      {
        providerInfo: 'secondKey',
        providerId: '\u00bd + \u00bc = \u00be',
        encryptedDataKey: new Uint8Array([6, 7, 8, 9, 0]),
      },
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
      messageId: new Uint8Array([
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
      ]),
      encryptionContext: {
        some: 'public',
        information: '\u00bd + \u00bc = \u00be',
      },
      encryptedDataKeys: [
        {
          providerInfo: 'firstKey',
          providerId: '\u00bd + \u00bc = \u00be',
          encryptedDataKey: new Uint8Array([1, 2, 3, 4, 5]),
        },
        {
          providerInfo: 'secondKey',
          providerId: '\u00bd + \u00bc = \u00be',
          encryptedDataKey: new Uint8Array([6, 7, 8, 9, 0]),
        },
      ],
      contentType: ContentType.FRAMED_DATA,
      headerIvLength: 12,
      frameLength: 4096,
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
      messageId: new Uint8Array([
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
      ]),
      encryptionContext: {},
      encryptedDataKeys: [
        {
          providerInfo: 'firstKey',
          providerId: '\u00bd + \u00bc = \u00be',
          encryptedDataKey: new Uint8Array([1, 2, 3, 4, 5]),
        },
        {
          providerInfo: 'secondKey',
          providerId: '\u00bd + \u00bc = \u00be',
          encryptedDataKey: new Uint8Array([6, 7, 8, 9, 0]),
        },
      ],
      contentType: ContentType.FRAMED_DATA,
      headerIvLength: 12,
      frameLength: 4096,
    })

    expect(test).to.be.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(97)
    expect(test).to.deep.equal(
      fixtures.zeroByteEncryptionContextMessageHeader()
    )
  })

  it('Precondition: Must be a version that can be serialized.', () => {
    const fromUtf8 = (input: string) => Buffer.from(input)
    const { serializeMessageHeader } = serializeFactory(fromUtf8)
    expect(() => serializeMessageHeader({ version: -1 } as any)).to.throw(
      'Unsupported version.'
    )
  })
})

describe('serializeMessageHeaderAuth', () => {
  const headerIv = new Uint8Array(12)
  const headerAuthTag = new Uint8Array(16)

  it('can serialize the v1 header auth', () => {
    const messageHeader: MessageHeaderV1 = {
      version: SerializationVersion.V1,
      type: ObjectType.CUSTOMER_AE_DATA,
      suiteId: 0x0014,
      // prettier-ignore
      messageId: new Uint8Array([
        3,  3,  3,  3,  3,  3,  3,  3,  3,
        3, 3, 3, 3, 3, 3, 3,
      ]),
      encryptionContext: {
        some: 'public',
        information: '\u00bd + \u00bc = \u00be',
      },
      encryptedDataKeys: [
        {
          providerInfo: 'firstKey',
          providerId: '\u00bd + \u00bc = \u00be',
          encryptedDataKey: new Uint8Array([1, 2, 3, 4, 5]),
        },
        {
          providerInfo: 'secondKey',
          providerId: '\u00bd + \u00bc = \u00be',
          encryptedDataKey: new Uint8Array([6, 7, 8, 9, 0]),
        },
      ],
      contentType: ContentType.FRAMED_DATA,
      headerIvLength: 12,
      frameLength: 4096,
    }
    const test = serializeMessageHeaderAuth({
      headerIv,
      headerAuthTag,
      messageHeader,
    })
    expect(test).to.deep.equal(new Uint8Array(12 + 16))
  })

  it('can serialize the v2 header auth', () => {
    const messageHeader: MessageHeaderV2 = {
      version: SerializationVersion.V2,
      suiteId: 0x0014,
      // prettier-ignore
      messageId: new Uint8Array([
        3,  3,  3,  3,  3,  3,  3,  3,  3,
        3, 3, 3, 3, 3, 3, 3,
      ]),
      encryptionContext: {
        some: 'public',
        information: '\u00bd + \u00bc = \u00be',
      },
      encryptedDataKeys: [
        {
          providerInfo: 'firstKey',
          providerId: '\u00bd + \u00bc = \u00be',
          encryptedDataKey: new Uint8Array([1, 2, 3, 4, 5]),
        },
        {
          providerInfo: 'secondKey',
          providerId: '\u00bd + \u00bc = \u00be',
          encryptedDataKey: new Uint8Array([6, 7, 8, 9, 0]),
        },
      ],
      contentType: ContentType.FRAMED_DATA,
      frameLength: 4096,
      suiteData: new Uint8Array(32),
    }
    const test = serializeMessageHeaderAuth({
      headerIv,
      headerAuthTag,
      messageHeader,
    })
    expect(test).to.deep.equal(new Uint8Array(16))
  })
})
