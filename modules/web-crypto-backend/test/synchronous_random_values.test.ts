// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
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
