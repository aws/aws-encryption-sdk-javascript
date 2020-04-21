// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { sha512 } from '../src/sha512'

// sha512('asdf')
const fixture = Buffer.from(
  'QBsJ6rPAE9TKVJIruAK+yP1TGBkrCnXyAdizcnQpCA+zN1kavT5ERTuVRVW3oIEuEIHDm3QCk/dl6ucx9aZe0Q==',
  'base64'
)

describe('WebCryptoCachingMaterialsManager', () => {
  it('can hash a string', async () => {
    const test = await sha512('asdf')
    expect(test).to.deep.equal(fixture)
  })

  it('can hash a Uint8Array', async () => {
    // the string 'asdf' as utf-8 encoded bytes
    const test = await sha512(Buffer.from([97, 115, 100, 102]))
    expect(test).to.deep.equal(fixture)
  })

  it('can hash a mix of arguments', async () => {
    // the string 'asdf' as a mix of strings and binary
    const test = await sha512(
      'a',
      new Uint8Array([115]),
      'd',
      Buffer.from([102])
    )
    expect(test).to.deep.equal(fixture)
  })
})
