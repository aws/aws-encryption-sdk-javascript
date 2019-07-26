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
const fixture = Buffer.from('QBsJ6rPAE9TKVJIruAK+yP1TGBkrCnXyAdizcnQpCA+zN1kavT5ERTuVRVW3oIEuEIHDm3QCk/dl6ucx9aZe0Q==', 'base64')

describe('WebCryptoCachingMaterialsManager', () => {
  it('can hash a string', async () => {
    const test = await sha512('asdf')
    expect(test).to.deep.equal(fixture)
  })

  it('can hash a Uint8Array', async () => {
    // the string 'asdf' as utf-8 encoded bytes
    const test = await sha512(Buffer.from([ 97, 115, 100, 102 ]))
    expect(test).to.deep.equal(fixture)
  })

  it('can hash a mix of arguments', async () => {
    // the string 'asdf' as a mix of strings and binary
    const test = await sha512('a', new Uint8Array([115]), 'd', Buffer.from([102]))
    expect(test).to.deep.equal(fixture)
  })
})
