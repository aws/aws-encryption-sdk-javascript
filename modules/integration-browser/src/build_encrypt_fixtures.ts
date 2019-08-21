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

import {
  EncryptManifestList, // eslint-disable-line no-unused-vars
  KeyList, // eslint-disable-line no-unused-vars
  KeyInfoTuple // eslint-disable-line no-unused-vars
} from './types'
import { randomBytes } from 'crypto'
import {
  AlgorithmSuiteIdentifier, // eslint-disable-line no-unused-vars
  EncryptionContext // eslint-disable-line no-unused-vars
} from '@aws-crypto/client-browser'
import { URL } from 'url'
import { readFileSync, writeFileSync } from 'fs'
import got from 'got'

/* This function interacts with manifest information
 * and produces the fixtures in the `fixtures`
 * that the karma server will consume to run tests.
 * This gives us 2 useful freedoms.
 * 1. The code is not tied to a specific copy of the manifest information
 * 2. The tests can be run on a subset of tests for debugging.
 */
export async function buildEncryptFixtures (fixtures: string, manifestFile: string, keyFile: string, testName?: string, slice?: string) {
  const [start = 0, end = 9999] = (slice || '').split(':').map(n => parseInt(n, 10))
  const { tests, plaintexts }: EncryptManifestList = await getParsedJSON(manifestFile)
  const { keys }: KeyList = await getParsedJSON(keyFile)

  const plaintextBytes: {[name: string]: string} = {}

  Object
    .keys(plaintexts)
    .forEach(name => {
      /* Generate random bites as per spec.
       * See: https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0003-awses-message-encryption.md#plaintexts
       */
      plaintextBytes[name] = randomBytes(10).toString('base64')
    })

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

    const {
      plaintext,
      'master-keys': masterKeys,
      algorithm,
      'frame-size': frameLength,
      'encryption-context': encryptionContext
    } = testInfo

    const keysInfo = <KeyInfoTuple[]>masterKeys.map(keyInfo => {
      const key = keys[keyInfo.key]
      if (!key) throw new Error(`no key for ${name}`)
      return [keyInfo, key]
    })

    /* I'm expecting that the encrypt function will throw if this is not a supported AlgorithmSuiteIdentifier */
    const suiteId = <AlgorithmSuiteIdentifier>parseInt(algorithm, 16)

    const test: EncryptTestVectorInfo = {
      name,
      keysInfo,
      plainTextData: plaintextBytes[plaintext],
      encryptOp: { suiteId, frameLength, encryptionContext }
    }

    writeFileSync(`${fixtures}/${name}.json`, JSON.stringify(test))
  }

  writeFileSync(`${fixtures}/encrypt_tests.json`, JSON.stringify(testNames))
}

export interface EncryptTestVectorInfo {
  name: string,
  keysInfo: KeyInfoTuple[],
  plainTextData: string,
  encryptOp: {
    suiteId: AlgorithmSuiteIdentifier,
    frameLength: number,
    encryptionContext: EncryptionContext
  }
}

async function getParsedJSON (thing: string) {
  try {
    const url = new URL(thing)
    if (url.protocol === 'file:') {
      return jsonAtPath(thing)
    } else {
      return jsonAtUrl(url)
    }
  } catch (ex) {
    return jsonAtPath(thing)
  }
}
async function jsonAtUrl (url: URL) {
  const { body } = await got(url)
  return JSON.parse(body)
}

function jsonAtPath (path: string) {
  const json = readFileSync(path, { encoding: 'utf-8' })
  return JSON.parse(json)
}
