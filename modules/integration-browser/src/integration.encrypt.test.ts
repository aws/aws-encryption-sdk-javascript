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

/* eslint-env jasmine */

import { encryptMaterialsManagerWebCrypto } from './decrypt_materials_manager_web_crypto'
import { fromBase64 } from '@aws-sdk/util-base64-browser'
import { encrypt, needs } from '@aws-crypto/client-browser'
import { toUtf8 } from '@aws-sdk/util-utf8-browser'

declare const expect: any
declare const __fixtures__: any
declare const fetch: any

const notSupportedMessages = [
  '192-bit AES keys are not supported',
  'frameLength out of bounds: 0 > frameLength >= 4294967295',
  'Unsupported right now'
]
describe('browser encrypt tests', function () {
  const tests = __fixtures__['fixtures/encrypt_tests']
  const decryptOracle = __fixtures__['fixtures/decrypt_oracle']

  for (const testName of tests) {
    it(testName, async () => {
      console.log(`start: ${testName}`)
      const response = await fetch(`base/fixtures/${testName}.json`)
      const { keysInfo, plainTextData, encryptOp } = await response.json()

      const plainText = fromBase64(plainTextData)
      try {
        const cmm = await encryptMaterialsManagerWebCrypto(keysInfo)
        const { cipherMessage } = await encrypt(cmm, plainText, encryptOp)
        const response = await fetch(decryptOracle, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'Accept': 'application/octet-stream'
          },
          body: cipherMessage
        })
        const body = await response.arrayBuffer()
        needs(response.ok, `Failed to decrypt: ${toUtf8(body)}`)
        expect(plainText).toEqual(new Uint8Array(body))
      } catch (e) {
        if (!notSupportedMessages.includes(e.message)) throw e
      }
    })
  }
})
