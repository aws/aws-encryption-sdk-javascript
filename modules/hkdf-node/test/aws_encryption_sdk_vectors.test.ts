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
