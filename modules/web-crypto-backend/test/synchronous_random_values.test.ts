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
import { synchronousRandomValues } from '../src/index'
import sinon from 'sinon'
import * as browserWindow from '@aws-sdk/util-locate-window'
import * as fixtures from './fixtures'

describe('synchronousRandomValues', () => {
  it('should return random values', () => {
    const test = synchronousRandomValues(5)
    expect(test).to.be.instanceOf(Uint8Array)
    expect(test).lengthOf(5)
  })

  it('should return msCrypto random values', () => {
    const { locateWindow } = browserWindow
    sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowIE11OnComplete)

    const test = synchronousRandomValues(5)
    expect(test).to.be.instanceOf(Uint8Array)
    expect(test).lengthOf(5)
    // The random is a stub, so I know the value
    expect(test).to.deep.equal(new Uint8Array(5).fill(1))

    // @ts-ignore
    browserWindow.locateWindow = locateWindow
  })
})
