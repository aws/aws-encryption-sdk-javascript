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
} from '@aws-crypto/client-node'
import { URL } from 'url'
import { readFileSync } from 'fs'
import got from 'got'

export async function getEncryptTestVectorIterator (manifestFile: string, keyFile: string) {
  const { tests, plaintexts }: EncryptManifestList = await getParsedJSON(manifestFile)
  const { keys }: KeyList = await getParsedJSON(keyFile)

  const plaintextBytes: {[name: string]: Buffer} = {}

  Object
    .keys(plaintexts)
    .forEach(name => {
      plaintextBytes[name] = randomBytes(plaintexts[name])
    })

  return (function * nextTest (): IterableIterator<EncryptTestVectorInfo> {
    for (const [name, testInfo] of Object.entries(tests)) {
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

      yield {
        name,
        keysInfo,
        plainTextData: plaintextBytes[plaintext],
        encryptOp: { suiteId, frameLength, encryptionContext }
      }
    }
  })()
}

export interface EncryptTestVectorInfo {
  name: string,
  keysInfo: KeyInfoTuple[],
  plainTextData: Buffer,
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
