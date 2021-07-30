#!/usr/bin/env node
// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import streamToPromise from 'stream-to-promise'
import { writeFileSync } from 'fs'
import {
  parseDecryptionFiles,
  readUriOnce,
  centralDirectory,
  StreamEntry,
  DecryptTest,
  KeyInfoTuple,
  DecryptionFixture,
} from '@aws-crypto/integration-vectors'

/* This function interacts with manifest information
 * and produces the fixtures in the `fixtures`
 * that the karma server will consume to run tests.
 * This gives us 2 useful freedoms.
 * 1. The code is not tied to a specific copy of the manifest information
 * 2. The tests can be run on a subset of tests for debugging.
 */
export async function buildDecryptFixtures(
  fixtures: string,
  vectorFile: string,
  testName?: string,
  slice?: string
): Promise<void> {
  const [start = 0, end = 9999] = (slice || '')
    .split(':')
    .map((n) => parseInt(n, 10))

  const filesMap: Map<string, StreamEntry> = await centralDirectory(vectorFile)

  const { tests, keys } = await parseDecryptionFiles(filesMap)
  const testNames: string[] = []
  let count = 0

  for (const [name, testInfo] of Object.entries(tests)) {
    count += 1

    if (testName) {
      if (name !== testName) continue
    }

    if (slice) {
      if (start >= count) continue
      if (count > end) continue
    }

    const {
      result,
      description,
      ciphertext,
      'master-keys': masterKeys,
      'decryption-method': decryptionMethod,
    }: DecryptTest = testInfo

    if (decryptionMethod == 'streaming-unsigned-only') {
      // We don't have streaming in the browser so this test is not supported
      continue
    }

    testNames.push(name)

    let resultContent: { plainText: string } | { errorDescription: string }

    if ('output' in result) {
      const plainTextInfo = filesMap.get(result.output.plaintext)
      if (!plainTextInfo)
        throw new Error(
          `no plaintext file for ${name}: ${result.output.plaintext}`
        )
      const plainTextBuffer = await readUriOnce(
        `file://${plainTextInfo.fileName}`,
        filesMap
      )
      resultContent = {
        plainText: plainTextBuffer.toString('base64'),
      }
    } else {
      resultContent = { errorDescription: result.error['error-description'] }
    }

    const cipherInfo = filesMap.get(ciphertext)
    if (!cipherInfo) throw new Error(`no file for ${name}: ${ciphertext}`)
    const cipherText = await streamToPromise(await cipherInfo.stream())

    const keysInfo = masterKeys.map((keyInfo) => {
      if (keyInfo.type === 'aws-kms-mrk-aware-discovery') {
        return [keyInfo] as KeyInfoTuple
      }
      const key = keys[keyInfo.key]
      if (!key) throw new Error(`no key for ${name}`)
      return [keyInfo, key] as KeyInfoTuple
    })
    const test: DecryptionFixture = {
      name,
      description,
      keysInfo,
      cipherFile: cipherInfo.fileName,
      cipherText: cipherText.toString('base64'),
      result: resultContent,
    }

    writeFileSync(`${fixtures}/${name}.json`, JSON.stringify(test))
  }

  writeFileSync(`${fixtures}/decrypt_tests.json`, JSON.stringify(testNames))
}
