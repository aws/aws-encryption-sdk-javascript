// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env jasmine */

import { encryptMaterialsManagerWebCrypto } from './decrypt_materials_manager_web_crypto'
import { fromBase64 } from '@aws-sdk/util-base64-browser'
import {
  buildClient,
  CommitmentPolicy,
  needs,
} from '@aws-crypto/client-browser'
import { toUtf8 } from '@aws-sdk/util-utf8-browser'
const { encrypt } = buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
declare const expect: any
declare const __fixtures__: any
declare const fetch: any

const notSupportedMessages = [
  '192-bit AES keys are not supported',
  'frameLength out of bounds: 0 > frameLength >= 4294967295',
  'Unsupported right now',
]

const tests = __fixtures__['fixtures/encrypt_tests']
const decryptOracle = __fixtures__['fixtures/decrypt_oracle']
const chunk = __fixtures__['fixtures/concurrency'] || 1

for (let i = 0, j = tests.length; i < j; i += chunk) {
  aGroup(chunk, tests.slice(i, i + chunk), decryptOracle)
}

function aGroup(groupNumber: number, tests: string[], decryptOracle: string) {
  describe(`'browser encrypt tests': ${groupNumber}`, () => {
    for (const testName of tests) {
      aTest(testName, decryptOracle)
    }
  })
}

function aTest(testName: string, decryptOracle: string) {
  it(testName, async () => {
    console.log(`start: ${testName}`)
    const response = await fetch(`base/fixtures/${testName}.json`)
    const { keysInfo, plainTextData, encryptOp } = await response.json()

    const plainText = fromBase64(plainTextData)
    try {
      const cmm = await encryptMaterialsManagerWebCrypto(keysInfo)
      const { result } = await encrypt(cmm, plainText, encryptOp)
      const response = await fetch(decryptOracle, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          Accept: 'application/octet-stream',
        },
        body: result,
      })
      const body = await response.arrayBuffer()
      needs(response.ok, `Failed to decrypt: ${toUtf8(body)}`)
      expect(plainText).toEqual(new Uint8Array(body))
    } catch (e) {
      if (!notSupportedMessages.includes(e.message)) throw e
    }
  })
}
