// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  serializeSignatureInfo,
  deserializeSignature,
} from '../src/signature_info'
import * as fixtures from './fixtures'

describe('serializeSignatureInfo', () => {
  it('returns signature info', () => {
    const test = serializeSignatureInfo(fixtures.ecdsaP256Signature())
    expect(test).to.deep.equal(fixtures.ecdsaP256SignatureInfo())
  })
})

describe('deserializeSignature', () => {
  it('returns the signature', () => {
    const test = deserializeSignature(fixtures.ecdsaP256SignatureInfo())
    expect(test).to.deep.equal(fixtures.ecdsaP256Signature())
  })

  it('Precondition: There must be information for a signature.', () => {
    expect(() => deserializeSignature({} as any)).to.throw()
    expect(() => deserializeSignature(new Uint8Array())).to.throw()
    expect(() => deserializeSignature(new Uint8Array(1))).to.throw()
    expect(() => deserializeSignature(new Uint8Array(2))).to.throw()
  })

  it('Precondition: The signature length must be positive.', () => {
    const badInfo = fixtures.ecdsaP256SignatureInfo()
    badInfo[1] = 0
    expect(() => deserializeSignature(badInfo)).to.throw()
  })

  it('Precondition: The data must match the serialized length.', () => {
    const badInfo = fixtures.ecdsaP256SignatureInfo()
    badInfo[1] = badInfo[1] + 1
    expect(() => deserializeSignature(badInfo)).to.throw()
  })
})
