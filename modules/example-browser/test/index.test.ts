// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { testAES } from '../src/aes_simple'
import { testCachingCMMExample } from '../src/caching_cmm'
import { testKmsSimpleExample } from '../src/kms_simple'
import { testMultiKeyringExample } from '../src/multi_keyring'
import { testRSA } from '../src/rsa_simple'
import { testFallback } from '../src/fallback'

describe('test', () => {
  it('testAES', async () => {
    const { plainText, plaintext } = await testAES()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testCachingCMMExample', async () => {
    const { plainText, plaintext } = await testCachingCMMExample()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testKmsSimpleExample', async () => {
    const { plainText, plaintext } = await testKmsSimpleExample()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testMultiKeyringExample', async () => {
    const { plainText, plaintext } = await testMultiKeyringExample()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testRSA', async () => {
    const { plainText, plaintext } = await testRSA()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testFallback', async () => {
    const { plainText, plaintext } = await testFallback()
    expect(plainText).to.deep.equal(plaintext)
  })
})
