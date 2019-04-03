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

export function needs (condition: any, errorMessage: string, Err: ErrorConstructor = Error) {
  if (!condition) {
    throw new Err(errorMessage)
  }
}
