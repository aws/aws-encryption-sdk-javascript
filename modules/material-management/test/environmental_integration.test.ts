// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'

function isNode(): boolean {
  return (
    Object.prototype.toString.call(
      // @ts-ignore
      typeof process !== 'undefined' ? process : 0
    ) === '[object process]'
  )
}

describe('environmental integration', () => {
  it('Node.js crypto exports timingSafeEqual for supported Node.js Versions.', () => {
    if (isNode()) {
      // @ts-ignore
      const { timingSafeEqual } = require('crypto') // eslint-disable-line @typescript-eslint/no-var-requires
      expect(typeof timingSafeEqual === 'function').to.equal(true)
    }
  })
})
