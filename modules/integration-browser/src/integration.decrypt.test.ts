// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env jasmine */

import { DecryptionFixture } from '@aws-crypto/integration-vectors'
import { buildClient, CommitmentPolicy } from '@aws-crypto/client-browser'
import { decryptionIntegrationBrowserTest } from './testDecryptFixture'

const { decrypt } = buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

// expect is from karma-jasmine
declare const expect: any //https://jasmine.github.io/api/edge/global.html#expect
//The following 2 are from karma
declare const __fixtures__: any
declare const fetch: any

const tests: string[] = __fixtures__['fixtures/decrypt_tests']
const chunk = __fixtures__['fixtures/concurrency'] || 1

for (let i = 0, j = tests.length; i < j; i += chunk) {
  decryptionIntegrationBrowserGroup(chunk, tests.slice(i, i + chunk))
}

async function loadATest(testName: string): Promise<DecryptionFixture> {
  const response = await fetch(`base/fixtures/${testName}.json`)
  const decryptionFixture: DecryptionFixture = await response.json()
  return decryptionFixture
}

function decryptionIntegrationBrowserGroup(
  groupNumber: number,
  tests: string[]
) {
  describe(`browser decryption vectors: ${groupNumber}`, () => {
    for (const testName of tests) {
      itDecryptionIntegrationBrowserTest(testName)
    }
  })
}

function itDecryptionIntegrationBrowserTest(testName: string): void {
  it(testName, async () =>
    decryptionIntegrationBrowserTest(await loadATest(testName), decrypt, expect)
  )
}
