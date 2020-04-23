// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { EncryptedDataKey } from '../src/encrypted_data_key'

describe('EncryptedDataKey', () => {
  it('should return well formed data', () => {
    const providerInfo = 'providerInfo'
    const providerId = 'providerId'
    const encryptedDataKey = new Uint8Array([1, 2, 3])

    const test = new EncryptedDataKey({
      providerInfo,
      providerId,
      encryptedDataKey,
    })

    expect(Object.isFrozen(test)).to.eql(true)
    expect(test.providerInfo).to.eql(providerInfo)
    expect(test.providerId).to.eql(providerId)
    expect(test.encryptedDataKey).to.deep.equal(encryptedDataKey)
  })

  it('providerInfo must be a string', () => {
    const providerInfo = 5
    const providerId = 'providerId'
    const encryptedDataKey = new Uint8Array([1, 2, 3])
    const badOp: any = { providerInfo, providerId, encryptedDataKey }

    expect(() => new EncryptedDataKey(badOp)).to.throw()
  })

  it('providerId must be a string', () => {
    const providerInfo = 'providerInfo'
    const providerId = 5
    const encryptedDataKey = new Uint8Array([1, 2, 3])
    const badOp: any = { providerInfo, providerId, encryptedDataKey }

    expect(() => new EncryptedDataKey(badOp)).to.throw()
  })

  it('encryptedDataKey must be a Uint8Array', () => {
    const providerInfo = 'providerInfo'
    const providerId = 'providerId'
    const encryptedDataKey = 'not a uint8array'
    const badOp: any = { providerInfo, providerId, encryptedDataKey }

    expect(() => new EncryptedDataKey(badOp)).to.throw()
  })
})
