// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createHmac, createHash } from 'crypto'
import { UnsupportedAlgorithm, KeyLengthError } from './errors'

/**
 * Factory function to curry the hash algorithm
 *
 * @param algorithm [String] The name of the hash algorithm to use
 * @return [Function] The extract function decorated with expand and verify functions
 */
export function HKDF(algorithm = 'sha256'): HKDFOutput {
  // Check the length and support
  const hashLength = (function () {
    try {
      return createHash(algorithm).digest().length
    } catch (ex) {
      throw new UnsupportedAlgorithm(algorithm)
    }
  })()

  // (<= 255*HashLen) from https://tools.ietf.org/html/rfc5869
  const maxLength = 255 * hashLength

  // decorate the return function
  extractExpand.extract = extract
  extractExpand.expand = expand

  return extractExpand

  // implementation

  /**
   * Extracts a prk and returns a function to expand the given initial key
   *
   * @param ikm [String|Buffer] The initial key
   * @param salt [String|Buffer] Optional salt for the extraction
   * @return [Function] expand function with the extracted key curried onto it
   */
  function extractExpand(
    ikm: string | Uint8Array,
    salt?: string | Uint8Array | false
  ) {
    const prk = extract(ikm, salt)
    return (length: number, info?: Uint8Array) => expand(prk, length, info)
  }

  /**
   * Extracts a prk and returns a function to expand the given initial key
   *
   * @param ikm [String|Buffer] The initial key
   * @param salt [String|Buffer] Optional salt for the extraction
   * @return [Buffer] the expanded key
   */
  function extract(
    ikm: string | Uint8Array,
    salt?: string | Uint8Array | false
  ) {
    const _salt = salt || Buffer.alloc(hashLength, 0).toString()
    return createHmac(algorithm, _salt).update(ikm).digest()
  }

  /**
   * Expands a given key
   *
   * @param prk [Buffer] The key to expand from
   * @param length [Number] The length of the expanded key
   * @param info [Buffer] Data to bind the expanded key to application/context specific information
   * @return [Buffer] the expanded
   */
  function expand(prk: Uint8Array, length: number, info?: Uint8Array) {
    if (length > maxLength) {
      throw new KeyLengthError(maxLength, algorithm)
    }

    info = info || Buffer.alloc(0)
    const N = Math.ceil(length / hashLength)
    const memo: Buffer[] = []

    /* L/length octets are returned from T(1)...T(N), and T(0) is definitionally empty/zero length.
     * Elide T(0) into the Buffer.alloc(0) case and then return L octets of T indexed 0...L-1.
     */
    for (let i = 0; i < N; i++) {
      memo[i] = createHmac(algorithm, prk)
        .update(memo[i - 1] || Buffer.alloc(0))
        .update(info)
        .update(Buffer.alloc(1, i + 1))
        .digest()
    }
    return Buffer.concat(memo, length)
  }
}

export interface Extract {
  (ikm: string | Uint8Array, salt?: string | Uint8Array | false): Buffer
}

export interface Expand {
  (prk: Uint8Array, length: number, info?: Uint8Array): Buffer
}

export interface HKDFOutput {
  (...args: Parameters<Extract>): (...args: Curry<Parameters<Expand>>) => Buffer
  extract: Extract
  expand: Expand
}

type Curry<T extends any[]> = ((...args: T) => void) extends (
  head: any,
  ...tail: infer U
) => any
  ? U
  : never
