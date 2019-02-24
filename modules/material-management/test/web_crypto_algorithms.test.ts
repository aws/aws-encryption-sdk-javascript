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

import { expect } from 'chai'
import 'mocha'
import {AlgorithmSuiteIdentifier} from '../src/algorithm_suites'
import {WebCryptoAlgorithmSuite} from '../src/web_crypto_algorithms'

describe('WebCryptoAlgorithmSuite', () => {
  it('should return WebCryptoAlgorithmSuite', () => {
    const test = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(test).to.be.instanceof(WebCryptoAlgorithmSuite)
    expect(Object.isFrozen(test)).to.equal(true)
  })

  it('should throw for an id that does not exist', () => {
    expect(() =>  new WebCryptoAlgorithmSuite(1111)).to.throw()
  })

  // Typescript is 'use strict' so these should throw
  // however if someone is not running 'use strict'
  // These changes will not take effect _if_ they throw here

  it('instance should be immutable', () => {
    const test: any = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => test.id = 0).to.throw()
    expect(() => test.name = 0).to.throw()
    expect(() => test.encryption = 0).to.throw()
    expect(() => test.keyLength = 0).to.throw()
    expect(() => test.ivLength = 0).to.throw()
    expect(() => test.tagLength = 0).to.throw()
    expect(() => test.cacheSafe = 0).to.throw()
    expect(() => test.kdf = 0).to.throw()
    expect(() => test.kdfHash = 0).to.throw()
    expect(() => test.signatureCurve = 0).to.throw()
    expect(() => test.signatureHash = 0).to.throw()

    // Make sure new properties can not be added
    // @ts-ignore
    expect(() => test.anything = 0).to.throw(/object is not extensible/)
  })

  it('prototype should be immutable', () => {
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.id = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.name = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.encryption = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.keyLength = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.ivLength = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.tagLength = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.cacheSafe = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.kdf = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.kdfHash = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.signatureCurve = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.signatureHash = 0).to.throw()
    expect(() => (<any>WebCryptoAlgorithmSuite).prototype.anything = 0).to.throw()
  })
})
