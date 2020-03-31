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
import { bytes2JWK } from '../src/index'

describe('bytes2JWK', () => {
  it('https://tools.ietf.org/html/rfc7515#appendix-C test vector', () => {
    const binary = new Uint8Array([3, 236, 255, 224, 193])
    const test = bytes2JWK(binary)
    expect(test.kty).to.equal('oct')
    expect(test.k).to.equal('A-z_4ME')
  })
})
