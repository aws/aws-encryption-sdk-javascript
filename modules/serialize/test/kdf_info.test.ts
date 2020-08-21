// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { kdfInfo, kdfCommitKeyInfo } from '../src/kdf_info'
import { Buffer } from 'buffer'
import {
  AlgorithmSuiteIdentifier,
  WebCryptoAlgorithmSuite,
} from '@aws-crypto/material-management'

describe('kdfInfo', () => {
  it('should produce appropriate info', () => {
    const messageId = Buffer.alloc(16, 1)
    const test = kdfInfo(0x0014, messageId)

    expect(test).to.instanceof(Uint8Array)
    expect(test.byteLength).to.eql(18)
    expect(test).to.deep.equal(
      new Uint8Array([0, 20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    )
  })

  it('Precondition: Info for non-committing suites *only*.', () => {
    const committingSuiteID =
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
    expect(() => kdfInfo(committingSuiteID, new Uint8Array(16))).to.throw(
      'Committing algorithm suite not supported.'
    )
  })
})

describe('kdfCommitKeyInfo', () => {
  it('should produce appropriate info', () => {
    const committingSuiteID =
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY
    const suite = new WebCryptoAlgorithmSuite(committingSuiteID)

    const { keyLabel, commitLabel } = kdfCommitKeyInfo(suite)

    expect(keyLabel).to.instanceof(Uint8Array)
    expect(commitLabel).to.instanceof(Uint8Array)

    expect(keyLabel).to.deep.equal(
      Buffer.concat([Buffer.from([0x04, 0x78]), Buffer.from('DERIVEKEY')])
    )
    expect(commitLabel).to.deep.equal(Buffer.from('COMMITKEY'))
  })

  it('Precondition: Info for committing algorithm suites only.', () => {
    const committingSuiteID =
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    const suite = new WebCryptoAlgorithmSuite(committingSuiteID)

    expect(() => kdfCommitKeyInfo(suite)).to.throw(
      'Non committing algorithm suite not supported.'
    )
  })
})
