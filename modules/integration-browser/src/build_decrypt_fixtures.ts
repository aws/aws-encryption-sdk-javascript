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

import {
  open,
  Entry, // eslint-disable-line no-unused-vars
  ZipFile // eslint-disable-line no-unused-vars
} from 'yauzl'
import streamToPromise from 'stream-to-promise'
import { writeFileSync } from 'fs'
import { Readable } from 'stream' // eslint-disable-line no-unused-vars

import { DecryptManifestList } from './types' // eslint-disable-line no-unused-vars

/* This function interacts with manifest information
 * and produces the fixtures in the `fixtures`
 * that the karma server will consume to run tests.
 * This gives us 2 useful freedoms.
 * 1. The code is not tied to a specific copy of the manifest information
 * 2. The tests can be run on a subset of tests for debugging.
 */
export async function buildDecryptFixtures (fixtures: string, vectorFile: string, testName?: string, slice?: string) {
  const [start = 0, end = 9999] = (slice || '').split(':').map(n => parseInt(n, 10))

  const filesMap = await centralDirectory(vectorFile)

  const readUriOnce = (() => {
    const cache = new Map()
    return async (uri: string) => {
      const has = cache.get(uri)
      if (has) return has
      const fileInfo = filesMap.get(uri)
      if (!fileInfo) throw new Error(`${uri} does not exist`)
      const buffer = await streamToPromise(await fileInfo.stream())
      cache.set(uri, buffer)
      return buffer
    }
  })()

  const manifestBuffer = await readUriOnce('file://manifest.json')
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
    const plainTextInfo = filesMap.get(plaintextFile)
    const cipherInfo = filesMap.get(ciphertext)
    if (!cipherInfo || !plainTextInfo) throw new Error(`no file for ${name}: ${ciphertext} | ${plaintextFile}`)

    const cipherText = await streamToPromise(await cipherInfo.stream())
    const plainText = await readUriOnce(`file://${plainTextInfo.fileName}`)
    const keysInfo = masterKeys.map(keyInfo => {
      const key = keys[keyInfo.key]
      if (!key) throw new Error(`no key for ${name}`)
      return [keyInfo, key]
    })

    const test = JSON.stringify({
      name,
      keysInfo,
      cipherFile: cipherInfo.fileName,
      cipherText: cipherText.toString('base64'),
      plainText: plainText.toString('base64')
    })

    writeFileSync(`${fixtures}/${name}.json`, test)
  }

  writeFileSync(`${fixtures}/decrypt_tests.json`, JSON.stringify(testNames))
}

interface StreamEntry extends Entry {
  stream: () => Promise<Readable>
}

function centralDirectory (vectorFile: string): Promise<Map<string, StreamEntry>> {
  const filesMap = new Map<string, StreamEntry>()
  return new Promise((resolve, reject) => {
    open(vectorFile, { lazyEntries: true, autoClose: false }, (err, zipfile) => {
      if (err || !zipfile) return reject(err)

      zipfile
        .on('entry', (entry: StreamEntry) => {
          entry.stream = curryStream(zipfile, entry)
          filesMap.set(`file://${entry.fileName}`, entry)
          zipfile.readEntry()
        })
        .on('end', () => {
          resolve(filesMap)
        })
        .on('error', (err) => reject(err))
        .readEntry()
    })
  })
}

function curryStream (zipfile: ZipFile, entry: Entry) {
  return function stream (): Promise<Readable> {
    return new Promise((resolve, reject) => {
      zipfile.openReadStream(entry, (err, readStream) => {
        if (err || !readStream) return reject(err)
        resolve(readStream)
      })
    })
  }
}
