// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  EncryptManifestList,
  KeyList,
  KeyInfoTuple,
} from '@aws-crypto/integration-vectors'
import { randomBytes } from 'crypto'
import {
  AlgorithmSuiteIdentifier,
  EncryptionContext,
} from '@aws-crypto/client-node'
import { URL } from 'url'
import { readFileSync } from 'fs'
import got from 'got'
import { ZipFile } from 'yazl'
import {
  KEYS_MANIFEST_NAME_FILENAME,
  MANIFEST_PLAINTEXT_PATH,
} from './constants'

export async function getEncryptTestVectorIterator(
  manifestFile: string,
  keyFile: string,
  manifestZip?: ZipFile
) {
  const [manifest, keys]: [EncryptManifestList, KeyList] = await Promise.all([
    getParsedJSON(manifestFile),
    getParsedJSON(keyFile),
  ])

  return _getEncryptTestVectorIterator(manifest, keys, manifestZip)
}

/* Just a simple more testable function */
export function _getEncryptTestVectorIterator(
  { tests, plaintexts }: EncryptManifestList,
  keysManifest: KeyList,
  manifestZip?: ZipFile
) {
  if (manifestZip) {
    // We assume that the keys manifest given for encrypt
    // has all the keys required for decrypt.
    manifestZip.addBuffer(
      Buffer.from(JSON.stringify(keysManifest)),
      `${KEYS_MANIFEST_NAME_FILENAME}`
    )
  }
  const { keys } = keysManifest
  const plaintextBytes: { [name: string]: Buffer } = {}

  Object.keys(plaintexts).forEach((name) => {
    plaintextBytes[name] = randomBytes(plaintexts[name])

    if (manifestZip) {
      manifestZip.addBuffer(
        plaintextBytes[name],
        `${MANIFEST_PLAINTEXT_PATH}${name}`
      )
    }
  })

  return (function* nextTest(): IterableIterator<EncryptTestVectorInfo> {
    for (const [name, testInfo] of Object.entries(tests)) {
      const {
        plaintext,
        'master-keys': masterKeys,
        algorithm,
        'frame-size': frameLength,
        'encryption-context': encryptionContext,
      } = testInfo
      const keysInfo = masterKeys.map((keyInfo) => {
        const key = keys[keyInfo.key]
        if (!key) throw new Error(`no key for ${name}`)
        return [keyInfo, key] as KeyInfoTuple
      })

      /* I'm expecting that the encrypt function will throw if this is not a supported AlgorithmSuiteIdentifier */
      const suiteId = parseInt(algorithm, 16) as AlgorithmSuiteIdentifier

      yield {
        name,
        keysInfo,
        plainTextData: plaintextBytes[plaintext],
        plaintextName: plaintext,
        encryptOp: { suiteId, frameLength, encryptionContext },
      }
    }
  })()
}

export interface EncryptTestVectorInfo {
  name: string
  keysInfo: KeyInfoTuple[]
  plainTextData: Buffer
  plaintextName: string
  encryptOp: {
    suiteId: AlgorithmSuiteIdentifier
    frameLength: number
    encryptionContext: EncryptionContext
  }
}

async function getParsedJSON(thing: string) {
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
async function jsonAtUrl(url: URL) {
  const { body } = await got(url)
  return JSON.parse(body)
}

function jsonAtPath(path: string) {
  const json = readFileSync(path, { encoding: 'utf-8' })
  return JSON.parse(json)
}
