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
  Open,
  File // eslint-disable-line no-unused-vars
} from 'unzipper'
import {
  DecryptManifestList, // eslint-disable-line no-unused-vars
  KeyList, // eslint-disable-line no-unused-vars
  KeyInfoTuple // eslint-disable-line no-unused-vars
} from './types'
import { Readable } from 'stream' // eslint-disable-line no-unused-vars

export async function getDecryptTestVectorIterator (vectorFile: string) {
  const centralDirectory = await Open.file(vectorFile)
  // @ts-ignore
  const filesMap = new Map(centralDirectory.files.map(file => [file.path, file]))

  return _getDecryptTestVectorIterator(filesMap)
}

/* Just a simple more testable function */
export async function _getDecryptTestVectorIterator (filesMap: Map<string, File>) {
  const readUriOnce = (() => {
    const cache: Map<string, Buffer> = new Map()
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
  const { keys }: KeyList = JSON.parse(keysBuffer.toString('utf8'))

  return (function * nextTest (): IterableIterator<TestVectorInfo> {
    for (const [name, testInfo] of Object.entries(tests)) {
      const { plaintext: plaintextFile, ciphertext, 'master-keys': masterKeys } = testInfo
      const plainTextInfo = filesMap.get(testUri2Path(plaintextFile))
      const cipherInfo = filesMap.get(testUri2Path(ciphertext))
      if (!cipherInfo || !plainTextInfo) throw new Error(`no file for ${name}: ${testUri2Path(ciphertext)} | ${testUri2Path(plaintextFile)}`)
      const cipherStream = cipherInfo.stream()
      const plainTextStream = plainTextInfo.stream()
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

function testUri2Path (uri: string) {
  return uri.replace('file://', '')
}

export interface TestVectorInfo {
  name: string,
  keysInfo: KeyInfoTuple[],
  cipherStream: Readable
  plainTextStream: Readable
}
