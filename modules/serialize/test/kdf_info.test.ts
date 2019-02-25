/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import { kdfInfo } from '../src/kdf_info'
import { Buffer } from 'buffer'

describe('kdfInfo', () => {
  it('should produce appropriate info', () => {
    const messageId = Buffer.alloc(16, 1)
    const test = kdfInfo(0x0014, messageId)

    expect(test).to.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(18)
    expect(test).to.deep.equal(new Uint8Array([0, 20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]))
  })
})
