// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  NodeRawAesMaterial,
  WebCryptoRawAesMaterial,
} from '../src/raw_aes_material'
import { RawAesWrappingSuiteIdentifier } from '../src/raw_aes_algorithm_suite'
import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management'

describe('NodeRawAesMaterial', () => {
  const suiteId = RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const test = new NodeRawAesMaterial(suiteId)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite.id === suiteId).to.equal(true))
  it('class is frozen', () =>
    expect(Object.isFrozen(NodeRawAesMaterial)).to.equal(true))
  it('class prototype is frozen', () =>
    expect(Object.isFrozen(NodeRawAesMaterial.prototype)).to.equal(true))
  it('hasValidKey is false', () => expect(test.hasValidKey()).to.equal(false))
  it('Precondition: NodeRawAesMaterial suiteId must be RawAesWrappingSuiteIdentifier.', () => {
    const suiteId =
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256 as any
    expect(() => new NodeRawAesMaterial(suiteId)).to.throw()
  })
})

describe('WebCryptoRawAesMaterial', () => {
  const suiteId = RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const test = new WebCryptoRawAesMaterial(suiteId)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite.id === suiteId).to.equal(true))
  it('class is frozen', () =>
    expect(Object.isFrozen(WebCryptoRawAesMaterial)).to.equal(true))
  it('class prototype is frozen', () =>
    expect(Object.isFrozen(WebCryptoRawAesMaterial.prototype)).to.equal(true))
  it('hasValidKey is false', () => expect(test.hasValidKey()).to.equal(false))
  it('Precondition: WebCryptoAlgorithmSuite suiteId must be RawAesWrappingSuiteIdentifier.', () => {
    const suiteId =
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256 as any
    expect(() => new WebCryptoRawAesMaterial(suiteId)).to.throw()
  })
})
