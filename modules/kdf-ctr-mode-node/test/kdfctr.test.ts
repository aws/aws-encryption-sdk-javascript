// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { expect } from 'chai'
import {
  INT32_MAX_LIMIT,
  increment,
  kdfCounterMode,
  rawDerive,
  SupportedDigestAlgorithms,
  SupportedDerivedKeyLengths,
} from '../src/kdfctr'
import { rawTestVectors, testVectors } from './testvectors'
import { createHash } from 'crypto'

describe('KDF Ctr Mode', () => {
  const ikm = Buffer.alloc(32)
  const nonce = Buffer.alloc(16)
  const digestAlgorithm = 'sha256'
  const expectedLength = 32
  const purpose = Buffer.from('aws-kms-hierarchy', 'utf-8')

  it('Purpose is optional', () =>
    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce,
        purpose: undefined,
        expectedLength,
      })
    ).to.not.throw())

  it('Precondition: the nonce is required', () => {
    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce: undefined,
        purpose,
        expectedLength,
      })
    ).to.throw('The nonce must be provided')
  })

  it('Precondition: the ikm must be 32 bytes long', () => {
    const invalidIkm = Buffer.alloc(31)
    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm: invalidIkm,
        nonce,
        purpose,
        expectedLength,
      })
    ).to.throw(`Unsupported IKM length ${invalidIkm.length}`)

    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm: Buffer.alloc(32),
        nonce,
        purpose,
        expectedLength,
      })
    ).to.not.throw()
  })

  it('Precondition: the nonce must be 16 bytes long', () => {
    const invalidNonce = Buffer.alloc(17)
    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce: invalidNonce,
        purpose,
        expectedLength,
      })
    ).to.throw(`Unsupported nonce length ${invalidNonce.length}`)

    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce: Buffer.alloc(16),
        purpose,
        expectedLength,
      })
    ).to.not.throw()
  })

  it('Precondition: the expected length must be 32 bytes', () => {
    const invalidExpectedLength = 31 as SupportedDerivedKeyLengths
    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce,
        purpose,
        expectedLength: invalidExpectedLength,
      })
    ).to.throw(`Unsupported requested length ${invalidExpectedLength}`)

    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce,
        purpose,
        expectedLength: 32,
      })
    ).to.not.throw()
  })

  it('Precondition: the expected length * 8 must be under the max 32-bit signed integer', () => {
    let invalidExpectedLength = (INT32_MAX_LIMIT /
      8) as SupportedDerivedKeyLengths
    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce,
        purpose,
        expectedLength: invalidExpectedLength,
      })
    ).to.throw(`Unsupported requested length ${invalidExpectedLength}`)

    invalidExpectedLength = -60 as SupportedDerivedKeyLengths
    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce,
        purpose,
        expectedLength: invalidExpectedLength,
      })
    ).to.throw(`Unsupported requested length ${invalidExpectedLength}`)
  })

  it('Precondition: the input length must be under the max 32-bit signed integer', () => {
    const invalidPurpose = Buffer.alloc(
      INT32_MAX_LIMIT - (4 + 4 + 1 + nonce.length)
    )
    expect(() =>
      kdfCounterMode({
        digestAlgorithm,
        ikm,
        nonce,
        purpose: invalidPurpose,
        expectedLength,
      })
    ).to.throw(
      `Input Length ${
        9 + invalidPurpose.length + nonce.length
      } must be under ${INT32_MAX_LIMIT} bytes`
    )

    expect(() =>
      setTimeout(() => {
        kdfCounterMode({
          digestAlgorithm,
          ikm,
          nonce,
          purpose: Buffer.alloc(
            INT32_MAX_LIMIT - (4 + 4 + 1 + nonce.length) - 1
          ),
          expectedLength,
        })
      }, 2000)
    ).to.not.throw()
  })

  describe('Raw derive', () => {
    const explicitInfo = Buffer.alloc(10)

    it('Precondition: expected length must be positive', () => {
      let invalidExpectedLength = -1
      expect(() =>
        rawDerive(ikm, explicitInfo, invalidExpectedLength, digestAlgorithm)
      ).to.throw(`Requested length ${invalidExpectedLength} must be positive`)

      invalidExpectedLength = 0
      expect(() =>
        rawDerive(ikm, explicitInfo, invalidExpectedLength, digestAlgorithm)
      ).to.throw(`Requested length ${invalidExpectedLength} must be positive`)

      expect(() =>
        rawDerive(ikm, explicitInfo, 1, digestAlgorithm)
      ).to.not.throw()
    })

    it('Precondition: length of explicit info + 4 bytes should be under the max 32-bit signed integer', () => {
      const invalidExplicitInfo = Buffer.alloc(INT32_MAX_LIMIT - 4)
      expect(() =>
        rawDerive(ikm, invalidExplicitInfo, expectedLength, digestAlgorithm)
      ).to.throw(
        `Explicit info length ${invalidExplicitInfo.length} must be under ${
          INT32_MAX_LIMIT - 4
        } bytes`
      )

      expect(() =>
        setTimeout(() => {
          rawDerive(
            ikm,
            Buffer.alloc(INT32_MAX_LIMIT - 4 - 1),
            expectedLength,
            digestAlgorithm
          )
        }, 2000)
      ).to.not.throw()
    })

    it('Precondition: the digest algorithm should be sha256', () => {
      const invalidDigestAlgorithm = 'sha512' as SupportedDigestAlgorithms
      expect(() =>
        rawDerive(ikm, explicitInfo, expectedLength, invalidDigestAlgorithm)
      ).to.throw(`Unsupported digest algorithm ${invalidDigestAlgorithm}`)

      expect(() =>
        rawDerive(ikm, explicitInfo, expectedLength, 'sha256')
      ).to.not.throw()
    })

    it('Precondition: the expected length + digest hash length should be under the max 32-bit signed integer - 1', () => {
      const macLengthBytes = createHash('sha256').digest().length
      const invalidExpectedLength = INT32_MAX_LIMIT - 1 - macLengthBytes
      expect(() =>
        rawDerive(ikm, explicitInfo, invalidExpectedLength, 'sha256')
      ).to.throw(
        `The combined requested and digest hash length ${
          invalidExpectedLength + macLengthBytes
        } must be under ${INT32_MAX_LIMIT - 1} bytes`
      )
    })
  })

  describe('Increment', () => {
    it('Precondition: buffer length must be 4 bytes', () => {
      let x = Buffer.alloc(5)
      expect(() => increment(x)).to.throw(
        `Buffer length ${x.length} must be 4 bytes`
      )

      x = Buffer.alloc(4)
      expect(() => increment(x)).to.not.throw()
    })

    it('Postcondition: incremented buffer length must be 4 bytes', () => {
      const a = Buffer.from([0, 0, 0, 250])
      expect(increment(a).length).equals(4)
      const b = Buffer.from([0, 0, 250, 255])
      expect(increment(b).length).equals(4)
      const c = Buffer.from([0, 250, 255, 255])
      expect(increment(c).length).equals(4)
      const d = Buffer.from([250, 255, 255, 255])
      expect(increment(d).length).equals(4)
    })

    it('4th byte is incremented', () => {
      const x = Buffer.from([0, 0, 0, 254])
      expect(increment(x)).to.deep.equals(Buffer.from([0, 0, 0, 255]))
    })

    it('3rd byte is incremented', () => {
      const x = Buffer.from([0, 0, 254, 255])
      expect(increment(x)).deep.equals(Buffer.from([0, 0, 255, 0]))
    })

    it('2nd byte is incremented', () => {
      const x = Buffer.from([0, 254, 255, 255])
      expect(increment(x)).deep.equals(Buffer.from([0, 255, 0, 0]))
    })

    it('1st byte is incremented', () => {
      const x = Buffer.from([254, 255, 255, 255])
      expect(increment(x)).deep.equals(Buffer.from([255, 0, 0, 0]))
    })

    it('Buffer is maxed out and cannot be incremented', () => {
      const x = Buffer.from([255, 255, 255, 255])
      expect(() => increment(x)).to.throw()
    })
  })

  describe('Test vectors', () => {
    describe('Raw derive', () => {
      for (const rawTestVector of rawTestVectors) {
        const { name, hash, ikm, info, L, okm } = rawTestVector
        it(name, () => {
          expect(rawDerive(ikm, info, L, hash)).to.deep.equals(okm)
        })
      }
    })

    for (const testVector of testVectors) {
      const { name, hash, ikm, info, L, okm, purpose } = testVector
      it(name, () => {
        expect(
          kdfCounterMode({
            digestAlgorithm: hash,
            ikm,
            nonce: info,
            purpose,
            expectedLength: L,
          })
        ).to.deep.equals(okm)
      })
    }
  })
})
