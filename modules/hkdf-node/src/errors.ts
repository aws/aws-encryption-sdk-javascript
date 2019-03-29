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

export class HKDFError extends Error {
  constructor (message?: string) {
    super(message)
    Object.setPrototypeOf(this, HKDFError.prototype)
  }
}

export class KeyLengthError extends HKDFError {
  public name = 'KeyLengthError'
  constructor (maxLength: number, algorithm: string) {
    super('Can not derive keys larger than ' + maxLength + ' for algorithm:' + algorithm)
    Object.setPrototypeOf(this, KeyLengthError.prototype)
  }
}

export class UnsupportedAlgorithm extends HKDFError {
  public name = 'UnsupportedAlgorithm'
  constructor (algorithm: string) {
    super('Hash algorithm: ' + algorithm + ' is not an implemented algorithm')
    Object.setPrototypeOf(this, UnsupportedAlgorithm.prototype)
  }
}
