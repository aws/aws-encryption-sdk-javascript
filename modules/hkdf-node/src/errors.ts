// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export class HKDFError extends Error {
  constructor(message?: string) {
    super(message)
    Object.setPrototypeOf(this, HKDFError.prototype)
  }
}

export class KeyLengthError extends HKDFError {
  public name = 'KeyLengthError'
  constructor(maxLength: number, algorithm: string) {
    super(
      'Can not derive keys larger than ' +
        maxLength +
        ' for algorithm:' +
        algorithm
    )
    Object.setPrototypeOf(this, KeyLengthError.prototype)
  }
}

export class UnsupportedAlgorithm extends HKDFError {
  public name = 'UnsupportedAlgorithm'
  constructor(algorithm: string) {
    super('Hash algorithm: ' + algorithm + ' is not an implemented algorithm')
    Object.setPrototypeOf(this, UnsupportedAlgorithm.prototype)
  }
}
