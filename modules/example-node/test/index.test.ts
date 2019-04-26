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
import { rsaTest } from '../src/rsa_simple'
import { kmsSimpleTest } from '../src/kms_simple'
import { kmsStreamTest } from '../src/kms_stream'
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
    await kmsStreamTest()
    const packageJson = readFileSync('./package.json', { encoding: 'utf8' })
    const test = readFileSync('./package.json.decrypt', { encoding: 'utf8' })

    expect(test).to.equal(packageJson)
  })
})
