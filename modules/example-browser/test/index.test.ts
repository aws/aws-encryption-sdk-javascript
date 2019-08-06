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
import { testAES } from '../src/aes_simple'
import { testCachingMaterialsManagerExample } from '../src/caching_materials_manager'
import { testKmsSimpleExample } from '../src/kms_simple'
import { testMultiKeyringExample } from '../src/multi_keyring'
import { testRSA } from '../src/rsa_simple'

describe('test', () => {
  it('testAES', async () => {
    const { plainText, clearMessage } = await testAES()
    expect(plainText).to.deep.equal(clearMessage)
  })

  it('testCachingMaterialsManagerExample', async () => {
    const { plainText, clearMessage } = await testCachingMaterialsManagerExample()
    expect(plainText).to.deep.equal(clearMessage)
  })

  it('testKmsSimpleExample', async () => {
    const { plainText, clearMessage } = await testKmsSimpleExample()
    expect(plainText).to.deep.equal(clearMessage)
  })

  it('testMultiKeyringExample', async () => {
    const { plainText, clearMessage } = await testMultiKeyringExample()
    expect(plainText).to.deep.equal(clearMessage)
  })

  it('testRSA', async () => {
    const { plainText, clearMessage } = await testRSA()
    expect(plainText).to.deep.equal(clearMessage)
  })
})
