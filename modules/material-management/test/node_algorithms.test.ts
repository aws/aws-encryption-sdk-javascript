// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { AlgorithmSuiteIdentifier } from '../src/algorithm_suites'
import { NodeAlgorithmSuite } from '../src/node_algorithms'

describe('NodeAlgorithmSuite', () => {
  it('should return WebCryptoAlgorithmSuite', () => {
    const test = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(test).to.be.instanceof(NodeAlgorithmSuite)
    expect(Object.isFrozen(test)).to.equal(true)
  })

  it('should throw for an id that does not exist', () => {
    expect(() => new NodeAlgorithmSuite(1111)).to.throw()
  })

  it('instance should be frozen', () => {
    const test = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(Object.isFrozen(test))
  })

  it('prototype should be frozen', () => {
    expect(Object.isFrozen(NodeAlgorithmSuite.prototype))
    expect(Object.isFrozen(NodeAlgorithmSuite))
  })
})
