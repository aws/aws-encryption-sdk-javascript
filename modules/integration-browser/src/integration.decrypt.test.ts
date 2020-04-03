// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env jasmine */

import { decryptMaterialsManagerWebCrypto } from './decrypt_materials_manager_web_crypto'
import { fromBase64 } from '@aws-sdk/util-base64-browser'
import { decrypt } from '@aws-crypto/client-browser'

declare const expect: any
declare const __fixtures__: any
declare const fetch: any

const notSupportedMessages = [
  '192-bit AES keys are not supported',
  'Unsupported right now'
]

const tests: string[] = __fixtures__['fixtures/decrypt_tests']
const chunk = __fixtures__['fixtures/concurrency'] || 1

for (let i = 0, j = tests.length; i < j; i += chunk) {
  aGroup(chunk, tests.slice(i, i + chunk))
}

function aGroup (groupNumber: number, tests: string[]) {
  describe(`browser decryption vectors: ${groupNumber}`, () => {
    for (const testName of tests) {
      aTest(testName)
    }
  })
}

function aTest (testName: string) {
  it(testName, async () => {
    console.log(`start: ${testName}`)
    const response = await fetch(`base/fixtures/${testName}.json`)
    const { keysInfo, cipherText, plainText } = await response.json()

    const cipher = fromBase64(cipherText)
    const good = fromBase64(plainText)
    try {
      const cmm = await decryptMaterialsManagerWebCrypto(keysInfo)
      const { plaintext } = await decrypt(cmm, cipher)
      expect(good).toEqual(plaintext)
    } catch (e) {
      if (!notSupportedMessages.includes(e.message)) throw e
    }
  })
}
