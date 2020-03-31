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
