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
import { serializeSignatureInfo, deserializeSignature } from '../src/signature_info'
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
