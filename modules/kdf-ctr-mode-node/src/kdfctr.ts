// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * Implementation of the https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf
 * Key Derivation in Counter Mode Using Pseudorandom Functions. This
 * implementation mirrors the Dafny one: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/src/KDF/KdfCtr.dfy
 */

import { createHash, createHmac } from 'crypto'
import { needs } from '@aws-crypto/material-management'
import { uInt32BE } from '@aws-crypto/serialize'

const SEPARATION_INDICATOR = Buffer.from([0x00])
const COUNTER_START_VALUE = 1
export const INT32_MAX_LIMIT = 2147483647
const SUPPORTED_IKM_LENGTHS = [32]
const SUPPORTED_NONCE_LENGTHS = [16]
const SUPPORTED_DERIVED_KEY_LENGTHS = [32]
const SUPPORTED_DIGEST_ALGORITHMS = ['sha256']

export type SupportedDigestAlgorithms = 'sha256'
export type SupportedDerivedKeyLengths = 32

interface KdfCtrInput {
  digestAlgorithm: SupportedDigestAlgorithms
  ikm: Buffer
  nonce?: Buffer
  purpose?: Buffer
  expectedLength: SupportedDerivedKeyLengths
}

export function kdfCounterMode({
  digestAlgorithm,
  ikm,
  nonce,
  purpose,
  expectedLength,
}: KdfCtrInput): Buffer {
  /* Precondition: the ikm must be 32 bytes long */
  needs(
    SUPPORTED_IKM_LENGTHS.includes(ikm.length),
    `Unsupported IKM length ${ikm.length}`
  )
  /* Precondition: the nonce is required */
  needs(nonce, 'The nonce must be provided')
  /* Precondition: the nonce must be 16 bytes long */
  needs(
    SUPPORTED_NONCE_LENGTHS.includes(nonce.length),
    `Unsupported nonce length ${nonce.length}`
  )
  /* Precondition: the expected length must be 32 bytes */
  /* Precondition: the expected length * 8 must be under the max 32-bit signed integer */
  needs(
    SUPPORTED_DERIVED_KEY_LENGTHS.includes(expectedLength) &&
      expectedLength * 8 < INT32_MAX_LIMIT &&
      expectedLength * 8 > 0,
    `Unsupported requested length ${expectedLength}`
  )

  const label = purpose || Buffer.alloc(0)
  const info = nonce || Buffer.alloc(0)
  const internalLength = 8 + SEPARATION_INDICATOR.length

  /* Precondition: the input length must be under the max 32-bit signed integer */
  needs(
    internalLength + label.length + info.length < INT32_MAX_LIMIT,
    `Input Length ${
      internalLength + label.length + info.length
    } must be under ${INT32_MAX_LIMIT} bytes`
  )

  const lengthBits = Buffer.from(uInt32BE(expectedLength * 8))
  const explicitInfo = Buffer.concat([
    label,
    SEPARATION_INDICATOR,
    info,
    lengthBits,
  ])

  return rawDerive(ikm, explicitInfo, expectedLength, digestAlgorithm)
}

export function rawDerive(
  ikm: Buffer,
  explicitInfo: Buffer,
  length: number,
  // omit offset as a parameter because it is unused, causing compile errors due
  // to configured project settings
  digestAlgorithm: SupportedDigestAlgorithms
): Buffer {
  const h = createHash(digestAlgorithm).digest().length

  /* Precondition: expected length must be positive */
  needs(length > 0, `Requested length ${length} must be positive`)
  /* Precondition: length of explicit info + 4 bytes should be under the max 32-bit signed integer */
  needs(
    4 + explicitInfo.length < INT32_MAX_LIMIT,
    `Explicit info length ${explicitInfo.length} must be under ${
      INT32_MAX_LIMIT - 4
    } bytes`
  )
  /* Precondition: the digest algorithm should be sha256 */
  needs(
    SUPPORTED_DIGEST_ALGORITHMS.includes(digestAlgorithm),
    `Unsupported digest algorithm ${digestAlgorithm}`
  )
  /* Precondition: the expected length + digest hash length should be under the max 32-bit signed integer - 1 */
  needs(
    length + h < INT32_MAX_LIMIT - 1,
    `The combined requested and digest hash length ${
      length + h
    } must be under ${INT32_MAX_LIMIT - 1} bytes`
  )

  // number of iterations calculated in accordance with SP800-108
  const iterations = Math.ceil(length / h)
  let buffer = Buffer.alloc(0)
  let i = Buffer.from(uInt32BE(COUNTER_START_VALUE))

  for (let iteration = 1; iteration <= iterations + 1; iteration++) {
    const digest = createHmac(digestAlgorithm, ikm)
      .update(i)
      .update(explicitInfo)
      .digest()
    buffer = Buffer.concat([buffer, digest])
    i = increment(i)
  }

  needs(buffer.length >= length, 'Failed to derive key of requested length')
  return buffer.subarray(0, length)
}

export function increment(x: Buffer): Buffer {
  /* Precondition: buffer length must be 4 bytes */
  needs(x.length === 4, `Buffer length ${x.length} must be 4 bytes`)

  let output: Buffer
  if (x[3] < 255) {
    output = Buffer.from([x[0], x[1], x[2], x[3] + 1])
  } else if (x[2] < 255) {
    output = Buffer.from([x[0], x[1], x[2] + 1, 0])
  } else if (x[1] < 255) {
    output = Buffer.from([x[0], x[1] + 1, 0, 0])
  } else if (x[0] < 255) {
    output = Buffer.from([x[0] + 1, 0, 0, 0])
  } else {
    throw new Error('Unable to derive key material; may have exceeded limit.')
  }

  /* Postcondition: incremented buffer length must be 4 bytes */
  needs(
    output.length === 4,
    `Incremented buffer length ${output.length} must be 4 bytes`
  )
  return output
}
