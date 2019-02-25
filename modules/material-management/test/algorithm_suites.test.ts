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
import { AlgorithmSuiteIdentifier, AlgorithmSuite } from '../src/algorithm_suites'

describe('AlgorithmSuiteIdentifier', () => {
  it('should be frozen', () => {
    expect(Object.isFrozen(AlgorithmSuiteIdentifier)).to.eql(true)
  })
})

describe('AlgorithmSuite', () => {
  it('should not allow an instance', () => {
    // @ts-ignore Trying to test something that Typescript should deny...
    expect(() => new AlgorithmSuite()).to.throw()
  })

  it('prototype should be immutable', () => {
    expect(Object.isFrozen(AlgorithmSuite.prototype))
  })
})
