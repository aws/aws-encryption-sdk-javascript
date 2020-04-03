// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { HKDF } from '../src/index'
import { testVectors } from './fixtures'

// See: https://github.com/aws/aws-encryption-sdk-c/blob/master/tests/unit/t_hkdf.c
describe('aws-encryption-sdk-c hkdf test vectors', () => {
  for (const vector of testVectors) {
    it(`Test: ${vector.testName}`, () => {
      const hdkf = HKDF(vector.whichSha)
      const test = hdkf(vector.ikm, vector.salt)(vector.okmLen, vector.info)
      expect(test).to.deep.equal(vector.okmDesired)
    })
  }
})
