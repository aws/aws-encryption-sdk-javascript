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
import { NodeRawAesMaterial, WebCryptoRawAesMaterial } from '../src/raw_aes_material'
import { RawAesWrappingSuiteIdentifier } from '../src/raw_aes_algorithm_suite'
import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management'

describe('NodeRawAesMaterial', () => {
  const suiteId = RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const test = new NodeRawAesMaterial(suiteId)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite.id === suiteId).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(NodeRawAesMaterial)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(NodeRawAesMaterial.prototype)).to.equal(true))
  it('hasValidKey is false', () => expect(test.hasValidKey()).to.equal(false))
  it('Precondition: NodeRawAesMaterial suiteId must be RawAesWrappingSuiteIdentifier.', () => {
    const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256 as any
    expect(() => new NodeRawAesMaterial(suiteId)).to.throw()
  })
})

describe('WebCryptoRawAesMaterial', () => {
  const suiteId = RawAesWrappingSuiteIdentifier.AES128_GCM_IV12_TAG16_NO_PADDING
  const test = new WebCryptoRawAesMaterial(suiteId)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite.id === suiteId).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(WebCryptoRawAesMaterial)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(WebCryptoRawAesMaterial.prototype)).to.equal(true))
  it('hasValidKey is false', () => expect(test.hasValidKey()).to.equal(false))
  it('Precondition: WebCryptoAlgorithmSuite suiteId must be RawAesWrappingSuiteIdentifier.', () => {
    const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256 as any
    expect(() => new WebCryptoRawAesMaterial(suiteId)).to.throw()
  })
})
