// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Preconditions, postconditions, and loop invariants are very
 * useful for safe programing.  They also document the specifications.
 * This function is to help simplify the semantic burden of parsing
 * these constructions.
 *
 * Instead of constructions like
 * if (!goodCondition) throw new Error('condition not true')
 *
 * needs(goodCondition, 'condition not true')
 */

export function needs(
  condition: any,
  errorMessage: string,
  Err: ErrorConstructor = Error
): asserts condition {
  if (!condition) {
    throw new Err(errorMessage)
  }
}
