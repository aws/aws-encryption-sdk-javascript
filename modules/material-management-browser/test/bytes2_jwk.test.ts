// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { bytes2JWK } from '../src/index'

describe('bytes2JWK', () => {
  it('https://tools.ietf.org/html/rfc7515#appendix-C test vector', () => {
    const binary = new Uint8Array([3, 236, 255, 224, 193])
    const test = bytes2JWK(binary)
    expect(test.kty).to.equal('oct')
    expect(test.k).to.equal('A-z_4ME')
  })
})
