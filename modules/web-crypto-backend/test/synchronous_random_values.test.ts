// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { generateSynchronousRandomValues } from '../src/synchronous_random_values'
import * as fixtures from './fixtures'

describe('synchronousRandomValues', () => {
  it('should return random values', () => {
    const synchronousRandomValues = generateSynchronousRandomValues(
      fixtures.fakeWindowWebCryptoSupportsZeroByteGCM
    )
    const test = synchronousRandomValues(5)
    expect(test).to.be.instanceOf(Uint8Array)
    expect(test).lengthOf(5)
  })
})
