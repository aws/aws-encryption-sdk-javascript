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
import {
  DecryptManifestList, // eslint-disable-line no-unused-vars
  KeyList, // eslint-disable-line no-unused-vars
  KeyInfoTuple // eslint-disable-line no-unused-vars
} from './types'
import { Readable } from 'stream' // eslint-disable-line no-unused-vars
import streamToPromise from 'stream-to-promise'

export async function getDecryptTestVectorIterator (vectorFile: string) {
  const filesMap = await centralDirectory(vectorFile)

  return _getDecryptTestVectorIterator(filesMap)
}

/* Just a simple more testable function */
export async function _getDecryptTestVectorIterator (filesMap: Map<string, StreamEntry>) {
  const readUriOnce = (() => {
    const cache: Map<string, Buffer> = new Map()
    return async (uri: string): Promise<Buffer> => {
      const has = cache.get(uri)
      if (has) return has
      const fileInfo = filesMap.get(uri)
      if (!fileInfo) throw new Error(`${uri} does not exist`)
      const stream = await fileInfo.stream()

      const buffer = await streamToPromise(stream)
      cache.set(uri, buffer)
      return buffer
    }
  })()

  const manifestBuffer = await readUriOnce('file://manifest.json')
  const { keys: keysFile, tests }: DecryptManifestList = JSON.parse(manifestBuffer.toString('utf8'))
  const keysBuffer = await readUriOnce(keysFile)
  const { keys }: KeyList = JSON.parse(keysBuffer.toString('utf8'))

  return (function * nextTest (): IterableIterator<TestVectorInfo> {
    for (const [name, testInfo] of Object.entries(tests)) {
      const { plaintext: plaintextFile, ciphertext, 'master-keys': masterKeys } = testInfo
      const plainTextInfo = filesMap.get(plaintextFile)
      const cipherInfo = filesMap.get(ciphertext)
      if (!cipherInfo || !plainTextInfo) throw new Error(`no file for ${name}: ${ciphertext} | ${plaintextFile}`)
      const cipherStream = cipherInfo.stream
      const plainTextStream = plainTextInfo.stream
      const keysInfo = <KeyInfoTuple[]>masterKeys.map(keyInfo => {
        const key = keys[keyInfo.key]
        if (!key) throw new Error(`no key for ${name}`)
        return [keyInfo, key]
      })

      yield {
        name,
        keysInfo,
        cipherStream,
        plainTextStream
      }
    }
  })()
}

export interface TestVectorInfo {
  name: string,
  keysInfo: KeyInfoTuple[],
  cipherStream: () => Promise<Readable>
  plainTextStream: () => Promise<Readable>
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
          filesMap.set('file://' + entry.fileName, entry)
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
