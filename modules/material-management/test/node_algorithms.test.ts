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
import { AlgorithmSuiteIdentifier } from '../src/algorithm_suites'
import { NodeAlgorithmSuite } from '../src/node_algorithms'

describe('NodeAlgorithmSuite', () => {
  it('should return WebCryptoAlgorithmSuite', () => {
    const test = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(test).to.be.instanceof(NodeAlgorithmSuite)
    expect(Object.isFrozen(test)).to.equal(true)
  })

  it('should throw for an id that does not exist', () => {
    expect(() => new NodeAlgorithmSuite(1111)).to.throw()
  })

  it('instance should be frozen', () => {
    const test = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(Object.isFrozen(test))
  })

  it('prototype should be frozen', () => {
    expect(Object.isFrozen(NodeAlgorithmSuite.prototype))
    expect(Object.isFrozen(NodeAlgorithmSuite))
  })
})
