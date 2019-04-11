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

/* These functions were built to provide a random range.
 * They are primarily used to calculate k in ECDSA signatures.
 * But are build to be useful elsewhere.
 * To satisfy the primary use case see
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf
 * Specifically Appendix
 * B.5.2 Per-Message Secret Number Generation by Testing Candidates
 */

import { needs } from '@aws-crypto/material-management'
import BN from 'bn.js'
import { randomBytes } from 'crypto'
/**
 * Returns a random number evenly distributed between 0 (inclusive) and bound (exclusive).
 * [0-bound) i.e. I will never return bound, but always a non-negative
 * number less than bound.
 * @param bound BN
 * @returns BN
 */
export function randomRangeBNjs (bound: BN) {
  /* Precondition: Needs to be a BN.js or I can not parse it. */
  needs(BN.isBN(bound), 'Must be a BN')
  /* Precondition: bound must be positive, 0 is negative... */
  needs(bound.gtn(0), 'Must be positive')

  const boundBitLength = bound.bitLength()
  const boundBytes = Math.ceil((boundBitLength) / 8)
  const bitDiff = (boundBytes * 8) - boundBitLength
  /* Check for early return (Postcondition): If bound is a power of 2 distribution is simple and even.
   * When bound is a power of 2, the number of bits needed line up nicely.
   * Take 2 ** 9 (512).  There are 10 bits in 512 but 0 - 511 (inclusive)
   * only needs 9 bits to represent every number.
   * Furthermore, there are no numbers that I need to discard.
   * So any random value of these 9 bits is a valid number 0 - 511
   */
  if (boundBitLength === bound.zeroBits() + 1) {
    /* Grab random bytes, and then unsigned shift off the extra bits.
     * Take the 512 example above.  10 Bits, but I will have 16 bits...
     * Because Math.ceil(10/8) === 2 and 2 Bytes is 16 Bits.
     */
    return new BN(randomBytes(boundBytes)).ushrn(bitDiff + 1)
  }

  let rand: BN
  do {
    /* Grab random bytes, and then unsigned shift off the extra bits.
     * Take the 512 example above.  10 Bits, but I will have 16 bits...
     * Because Math.ceil(10/8) === 2 and 2 Bytes is 16 Bits.
     */
    rand = new BN(randomBytes(boundBytes)).ushrn(bitDiff)
    /* I now have a number that has the right number of bits.
     * It may still be to large.
     * Simply compressing the number
     * This is not constant time and I do not believe it has to be.
     */
  } while (rand.gte(bound))

  return rand
}
