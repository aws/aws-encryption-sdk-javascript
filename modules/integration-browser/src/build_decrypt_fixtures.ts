#!/usr/bin/env node
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

import { Open } from 'unzipper'
import streamToPromise from 'stream-to-promise'
import { writeFileSync } from 'fs'

import { DecryptManifestList } from './types' // eslint-disable-line no-unused-vars

/* This function interacts with manifest information
 * and produces the fixtures in the `fixtures`
 * that the karma server will consume to run tests.
 * This gives us 2 useful freedoms.
 * 1. The code is not tied to a specific copy of the manifest information
 * 2. The tests can be run on a subset of tests for debugging.
 */
export async function buildDecryptFixtures (fixtures: string, vectorFile: string, testName: string, slice: string) {
  const [start = 0, end = 9999] = (slice || '').split(':').map(n => parseInt(n, 10))

  const centralDirectory = await Open.file(vectorFile)
  const filesMap = new Map(centralDirectory.files.map(file => [file.path, file]))

  const readUriOnce = (() => {
    const cache = new Map()
    return async (uri: string) => {
      const has = cache.get(uri)
      if (has) return has
      const fileInfo = filesMap.get(testUri2Path(uri))
      if (!fileInfo) throw new Error(`${uri} does not exist`)
      const buffer = await fileInfo.buffer()
      cache.set(uri, buffer)
      return buffer
    }
  })()

  const manifestBuffer = await readUriOnce('manifest.json')
  const { keys: keysFile, tests }: DecryptManifestList = JSON.parse(manifestBuffer.toString('utf8'))
  const keysBuffer = await readUriOnce(keysFile)
  const { keys } = JSON.parse(keysBuffer.toString('utf8'))
  const testNames = []
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

    testNames.push(name)

    const { plaintext: plaintextFile, ciphertext, 'master-keys': masterKeys } = testInfo
    const plainTextInfo = filesMap.get(testUri2Path(plaintextFile))
    const cipherInfo = filesMap.get(testUri2Path(ciphertext))
    if (!cipherInfo || !plainTextInfo) throw new Error(`no file for ${name}: ${ciphertext} | ${plaintextFile}`)

    const cipherText = await streamToPromise(<NodeJS.ReadableStream>cipherInfo.stream())
    const plainText = await readUriOnce(plainTextInfo.path)
    const keysInfo = masterKeys.map(keyInfo => {
      const key = keys[keyInfo.key]
      if (!key) throw new Error(`no key for ${name}`)
      return [keyInfo, key]
    })

    const test = JSON.stringify({
      name,
      keysInfo,
      cipherFile: cipherInfo.path,
      cipherText: cipherText.toString('base64'),
      plainText: plainText.toString('base64')
    })

    writeFileSync(`${fixtures}/${name}.json`, test)
  }

  writeFileSync(`${fixtures}/decrypt_tests.json`, JSON.stringify(testNames))
}

function testUri2Path (uri: string) {
  return uri.replace('file://', '')
}
