// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { flattenMixedCryptoKey, verify } from '../src/get_import_options'

chai.use(chaiAsPromised)
const { expect } = chai

describe('flattenMixedCryptoKey', () => {
  it('Check for early return (Postcondition): empty inputs should return an empty array.', () => {
    const test = flattenMixedCryptoKey()
    expect(test).to.be.an('array').with.lengthOf(0)
  })

  it('flattens a mixed crypto key', () => {
    const key = {
      algorithm: 'algo',
      type: 'secret',
      usages: ['encrypt'],
      extractable: false,
    }
    const mixedKey: any = { zeroByteCryptoKey: key, nonZeroByteCryptoKey: key }

    const test = flattenMixedCryptoKey(mixedKey)
    expect(test).to.be.an('array').with.lengthOf(2)
  })

  it('Postcondition: Not all keys are CryptoKeys.', () => {
    const key = {
      algorithm: 'algo',
      type: 'secret',
      usages: ['encrypt'],
      extractable: false,
    }
    const notKey: any = {}
    expect(() =>
      flattenMixedCryptoKey({
        zeroByteCryptoKey: notKey,
        nonZeroByteCryptoKey: key,
      } as any)
    ).to.throw('Not all keys are CryptoKeys.')
    expect(() =>
      flattenMixedCryptoKey({
        zeroByteCryptoKey: notKey,
        nonZeroByteCryptoKey: notKey,
      } as any)
    ).to.throw('Not all keys are CryptoKeys.')
    expect(() =>
      flattenMixedCryptoKey({ zeroByteCryptoKey: key } as any)
    ).to.throw('Not all keys are CryptoKeys.')
    expect(() =>
      flattenMixedCryptoKey({ nonZeroByteCryptoKey: key } as any)
    ).to.throw('Not all keys are CryptoKeys.')
  })
})

describe('verify', () => {
  it('verifies that all wrapping algorithms are valid', () => {
    const wrapping: any = {
      name: 'RSA-OAEP',
      hash: { name: 'SHA-1' },
    }
    const test = verify(wrapping, wrapping)
    expect(test === wrapping).to.equal(true)
  })

  it('Precondition: Need at least 1 algorithm to verify.', () => {
    expect(() => verify()).to.throw(
      'Can not verify an empty set of algorithms.'
    )
  })

  it('Precondition: The wrappingAlgorithm name must be a supported value.', () => {
    const wrapping: any = {
      name: 'not supported',
      hash: { name: 'SHA-1' },
    }
    expect(() => verify(wrapping)).to.throw('Algorithm name is not supported.')
  })

  it('Precondition: The hash name must be a supported value.', () => {
    const wrapping: any = {
      name: 'RSA-OAEP',
      hash: { name: 'not supported' },
    }
    expect(() => verify(wrapping)).to.throw('Hash name is not supported.')
  })

  it('Check for early return (Postcondition): Only 1 wrappingAlgorithm is clearly valid.', () => {
    const wrapping: any = {
      name: 'RSA-OAEP',
      hash: { name: 'SHA-1' },
    }
    const test = verify(wrapping)
    expect(test === wrapping).to.equal(true)
  })

  it('Precondition: All keys must have the same wrappingAlgorithm.', () => {
    const wrapping: any = {
      name: 'RSA-OAEP',
      hash: { name: 'SHA-1' },
    }
    const differentWrapping: any = {
      name: 'RSA-OAEP',
      hash: { name: 'SHA-512' },
    }
    expect(() => verify(wrapping, differentWrapping)).to.throw(
      'Not all RSA keys have the same wrappingAlgorithm.'
    )
  })
})
