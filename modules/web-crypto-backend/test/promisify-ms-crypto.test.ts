// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import promisifyMsSubtleCrypto from '../src/promisify-ms-crypto'
import * as fixtures from './fixtures'

chai.use(chaiAsPromised)
const { expect } = chai

/* These tests are very simple
 * I am not testing every subtle function
 * because the promisify code is all the same.
 */
describe('promisifyMsSubtleCrypto', () => {
  const backendComplete = promisifyMsSubtleCrypto(
    fixtures.fakeWindowIE11OnComplete.msCrypto.subtle
  )
  const backendError = promisifyMsSubtleCrypto(
    fixtures.fakeWindowIE11OnError.msCrypto.subtle
  )

  it('backendComplete:decrypt', async () => {
    // @ts-ignore These methods are stubs, ignore ts errors
    const test = await backendComplete.decrypt()
    expect(test).to.equal(true)
  })

  it('backendError:decrypt', async () => {
    // @ts-ignore These methods are stubs, ignore ts errors
    await expect(backendError.decrypt()).to.rejectedWith(Error)
  })
})
