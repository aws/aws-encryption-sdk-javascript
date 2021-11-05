// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
export class NotSupported extends Error {
  code: string

  constructor(message?: string) {
    super(message)
    Object.setPrototypeOf(this, NotSupported.prototype)
    this.code = 'NOT_SUPPORTED'
  }
}
