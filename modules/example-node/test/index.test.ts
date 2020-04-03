// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { rsaTest } from '../src/rsa_simple'
import { kmsSimpleTest } from '../src/kms_simple'
import { kmsStreamTest } from '../src/kms_stream'
import { aesTest } from '../src/aes_simple'
import { multiKeyringTest } from '../src/multi_keyring'
import { cachingCMMNodeSimpleTest } from '../src/caching_cmm'
import { readFileSync } from 'fs'

describe('test', () => {
  it('rsa', async () => {
    const { cleartext, plaintext } = await rsaTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kms', async () => {
    const { cleartext, plaintext } = await kmsSimpleTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kms', async () => {
    const test = await kmsStreamTest(__filename)
    const clearFile = readFileSync(__filename)

    expect(test).to.deep.equal(clearFile)
  })

  it('aes', async () => {
    const { cleartext, plaintext } = await aesTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('multi keyring', async () => {
    const { cleartext, plaintext } = await multiKeyringTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('caching CMM node', async () => {
    const { cleartext, plaintext } = await cachingCMMNodeSimpleTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })
})
