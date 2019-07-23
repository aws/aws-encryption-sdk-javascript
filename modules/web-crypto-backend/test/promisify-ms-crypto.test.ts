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

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import 'mocha'
import promisifyMsSubtleCrypto from '../src/promisify-ms-crypto'
import * as fixtures from './fixtures'

chai.use(chaiAsPromised)
const { expect } = chai

/* These tests are very simple
 * I am not testing every subtle function
 * because the promisify code is all the same.
 */
describe('promisifyMsSubtleCrypto', () => {
  const backendComplete = promisifyMsSubtleCrypto(fixtures.fakeWindowIE11OnComplete.msCrypto.subtle)
  const backendError = promisifyMsSubtleCrypto(fixtures.fakeWindowIE11OnError.msCrypto.subtle)

  it('backendComplete:decrypt', async () => {
    // @ts-ignore These methods are stubs, ignore ts errors
    const test = await backendComplete.decrypt()
    expect(test).to.equal(true)
  })

  it('backendError:decrypt', () => {
    // @ts-ignore These methods are stubs, ignore ts errors
    expect(backendError.decrypt()).to.rejectedWith(Error)
  })
})
