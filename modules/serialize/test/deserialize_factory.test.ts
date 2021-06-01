// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { deserializeFactory } from '../src/deserialize_factory'
import { WebCryptoAlgorithmSuite } from '@aws-crypto/material-management'
import * as fixtures from './fixtures'
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString()

describe('deserializeFactory:deserializeMessageHeader', () => {
  it('valid buffers return false', () => {
    const { deserializeMessageHeader } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    // valid buffers all request more data.
    expect(deserializeMessageHeader(new Uint8Array())).to.equal(false)
    expect(deserializeMessageHeader(new Uint8Array([1]))).to.equal(false)
    expect(deserializeMessageHeader(new Uint8Array([2]))).to.equal(false)
  })

  it('Precondition: A valid deserializer must exist.', () => {
    const { deserializeMessageHeader } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    expect(() => deserializeMessageHeader(new Uint8Array([10]))).to.throw(
      'Not a supported message format version.'
    )
  })

  it('plumbs maxEncryptedDataKeys through', () => {
    const { deserializeMessageHeader } = deserializeFactory(
      toUtf8,
      WebCryptoAlgorithmSuite
    )

    expect(() =>
      deserializeMessageHeader(fixtures.threeEdksMessagePartialHeaderV2(), {
        maxEncryptedDataKeys: 1,
      })
    ).to.throw('maxEncryptedDataKeys exceeded.')
  })
})
