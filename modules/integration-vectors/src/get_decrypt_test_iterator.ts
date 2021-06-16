// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { open, Entry, ZipFile } from 'yauzl'
import {
  DecryptManifestList,
  KeyList,
  KeyInfoTuple,
  StreamEntry,
  DecryptTest,
  KMSKey,
  AESKey,
  RSAKey,
  TestVectorInfo,
} from './types'
import streamToPromise from 'stream-to-promise'
import { Readable } from 'stream'
// noinspection JSUnusedGlobalSymbols
export async function parseIntegrationTestVectorsToTestVectorIterator(
  vectorFile: string
): Promise<IterableIterator<TestVectorInfo>> {
  const filesMap = await centralDirectory(vectorFile)
  return _getDecryptTestVectorIterator(filesMap)
}

export async function readUriOnce(
  uri: string,
  filesMap: Map<string, StreamEntry>
): Promise<Buffer> {
  const cache: Map<string, Buffer> = new Map()
  const has = cache.get(uri)
  if (has) return has
  const fileInfo = filesMap.get(uri)
  if (!fileInfo) throw new Error(`${uri} does not exist`)
  const stream = await fileInfo.stream()
  const buffer = await streamToPromise(stream)
  cache.set(uri, buffer)
  return buffer
}

export async function parseDecryptionFiles(
  filesMap: Map<string, StreamEntry>
): Promise<{
  tests: { [name: string]: DecryptTest }
  keys: { [name: string]: KMSKey | AESKey | RSAKey }
}> {
  const manifestBuffer = await readUriOnce('file://manifest.json', filesMap)
  const { keys: keysFile, tests }: DecryptManifestList = JSON.parse(
    manifestBuffer.toString('utf8')
  )
  const keysBuffer = await readUriOnce(keysFile, filesMap)
  const { keys }: KeyList = JSON.parse(keysBuffer.toString('utf8'))
  return { tests, keys }
}

/* Just a simple more testable function */
export async function _getDecryptTestVectorIterator(
  filesMap: Map<string, StreamEntry>
): Promise<IterableIterator<TestVectorInfo>> {
  const { tests, keys } = await parseDecryptionFiles(filesMap)
  return (function* nextTest(): IterableIterator<TestVectorInfo> {
    for (const [name, testInfo] of Object.entries(tests)) {
      const {
        description,
        result,
        ciphertext,
        'master-keys': masterKeys,
        'decryption-method': decryptionMethod,
      } = testInfo
      const cipherInfo = filesMap.get(ciphertext)
      if (!cipherInfo) throw new Error(`no file for ${name}: ${ciphertext}`)
      const cipherStream = cipherInfo.stream

      const keysInfo = masterKeys.map((keyInfo) => {
        if (keyInfo.type === 'aws-kms-mrk-aware-discovery') {
          return [keyInfo] as KeyInfoTuple
        }
        const key = keys[keyInfo.key]
        if (!key) throw new Error(`no key for ${name}`)
        return [keyInfo, key] as KeyInfoTuple
      })

      if (result && 'output' in result) {
        const plainTextInfo = filesMap.get(result.output.plaintext)
        if (!plainTextInfo)
          throw new Error(
            `no plaintext file for ${name}: ${result.output.plaintext}`
          )
        //Yield Positive Decryption Test
        yield {
          name,
          description,
          keysInfo,
          cipherStream,
          decryptionMethod,
          plainTextStream: plainTextInfo.stream,
        }
      } else if (result && 'error' in result) {
        //Yield Negative Decryption Test
        yield {
          name,
          description,
          keysInfo,
          cipherStream,
          decryptionMethod,
          errorDescription: result.error['error-description'],
        }
      } else {
        throw new Error(`Could not parse vector for ${name}`)
      }
    }
  })()
}

//No Unit Test Coverage
export async function centralDirectory(
  vectorFile: string
): Promise<Map<string, StreamEntry>> {
  const filesMap = new Map<string, StreamEntry>()
  return new Promise((resolve, reject) => {
    open(
      vectorFile,
      { lazyEntries: true, autoClose: false },
      (err, zipfile) => {
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
      }
    )
  })
}

//No Unit Test Coverage
export function curryStream(zipfile: ZipFile, entry: Entry) {
  return async function stream(): Promise<Readable> {
    return new Promise((resolve, reject) => {
      zipfile.openReadStream(entry, (err, readStream) => {
        if (err || !readStream) return reject(err)
        resolve(readStream)
      })
    })
  }
}
