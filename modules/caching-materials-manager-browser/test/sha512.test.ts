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
import { sha512 } from '../src/sha512'

// sha512('asdf')
const fixture = new Uint8Array([64, 27, 9, 234, 179, 192, 19, 212, 202, 84, 146, 43, 184, 2, 190, 200, 253, 83, 24, 25, 43, 10, 117, 242, 1, 216, 179, 114, 116, 41, 8, 15, 179, 55, 89, 26, 189, 62, 68, 69, 59, 149, 69, 85, 183, 160, 129, 46, 16, 129, 195, 155, 116, 2, 147, 247, 101, 234, 231, 49, 245, 166, 94, 209])

describe('WebCryptoCachingMaterialsManager', () => {
  it('can hash a string', async () => {
    const test = await sha512('asdf')
    expect(test).to.deep.equal(fixture)
  })

  it('can hash a Uint8Array', async () => {
    // the string 'asdf' as utf-8 encoded bytes
    const test = await sha512(new Uint8Array([ 97, 115, 100, 102 ]))
    expect(test).to.deep.equal(fixture)
  })

  it('can hash a mix of arguments', async () => {
    // the string 'asdf' as a mix of strings and binary
    const test = await sha512('a', new Uint8Array([115]), 'd', new Uint8Array([102]))
    expect(test).to.deep.equal(fixture)
  })
})
