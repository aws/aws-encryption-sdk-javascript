// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { AlgorithmSuiteIdentifier } from '../src/algorithm_suites'
import { WebCryptoAlgorithmSuite } from '../src/web_crypto_algorithms'

describe('WebCryptoAlgorithmSuite', () => {
  it('should return WebCryptoAlgorithmSuite', () => {
    const test = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(test).to.be.instanceof(WebCryptoAlgorithmSuite)
    expect(Object.isFrozen(test)).to.equal(true)
  })

  it('should throw for an id that does not exist', () => {
    expect(() => new WebCryptoAlgorithmSuite(1111)).to.throw()
  })

  it('instance should be immutable', () => {
    const test = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(Object.isFrozen(test)).to.equal(true)
  })

  it('prototype should be immutable', () => {
    expect(Object.isFrozen(WebCryptoAlgorithmSuite)).to.equal(true)
    expect(Object.isFrozen(WebCryptoAlgorithmSuite.prototype)).to.equal(true)
  })

  it('Precondition: Browsers do not support 192 bit keys so the AlgorithmSuiteIdentifier is removed.', () => {
    expect(
      () =>
        new WebCryptoAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16
        )
    ).to.throw()
    expect(
      () =>
        new WebCryptoAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA256
        )
    ).to.throw()
    expect(
      () =>
        new WebCryptoAlgorithmSuite(
          AlgorithmSuiteIdentifier.ALG_AES192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
        )
    ).to.throw()
  })
})
