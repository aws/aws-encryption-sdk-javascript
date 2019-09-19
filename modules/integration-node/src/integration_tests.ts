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
  TestVectorInfo, // eslint-disable-line no-unused-vars
  getDecryptTestVectorIterator
} from './get_decrypt_test_iterator'
import {
  EncryptTestVectorInfo, // eslint-disable-line no-unused-vars
  getEncryptTestVectorIterator
} from './get_encrypt_test_iterator'
import { decryptMaterialsManagerNode, encryptMaterialsManagerNode } from './decrypt_materials_manager_node'
import { decrypt, encrypt, needs } from '@aws-crypto/client-node'
import { URL } from 'url'
import got from 'got'

const notSupportedDecryptMessages = [
  'Not supported at this time.'
]

const notSupportedEncryptMessages = [
  'frameLength out of bounds: 0 > frameLength >= 4294967295',
  'Not supported at this time.'
]

// This is only viable for small streams, if we start get get larger streams, an stream equality should get written
export async function testDecryptVector ({ name, keysInfo, plainTextStream, cipherStream }: TestVectorInfo): Promise<TestVectorResults> {
  try {
    const cmm = decryptMaterialsManagerNode(keysInfo)
    const knowGood: Buffer[] = []
    plainTextStream.on('data', (chunk: Buffer) => knowGood.push(chunk))
    const { plaintext } = await decrypt(cmm, cipherStream)
    const result = Buffer.concat(knowGood).equals(plaintext)
    return { result, name }
  } catch (err) {
    return { result: false, name, err }
  }
}

// This is only viable for small streams, if we start get get larger streams, an stream equality should get written
export async function testEncryptVector ({ name, keysInfo, encryptOp, plainTextData }: EncryptTestVectorInfo, decryptOracle: URL): Promise<TestVectorResults> {
  try {
    const cmm = encryptMaterialsManagerNode(keysInfo)
    const { result: encryptResult } = await encrypt(cmm, plainTextData, encryptOp)

    const decryptResponse = await got.post(decryptOracle, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Accept': 'application/octet-stream'
      },
      body: encryptResult,
      encoding: null
    })
    needs(decryptResponse.statusCode === 200, 'decrypt failure')
    const { body } = decryptResponse
    const result = plainTextData.equals(body)
    return { result, name }
  } catch (err) {
    return { result: false, name, err }
  }
}

export async function integrationDecryptTestVectors (vectorFile: string, tolerateFailures: number = 0, testName?: string) {
  const tests = await getDecryptTestVectorIterator(vectorFile)
  let failureCount = 0
  for (const test of tests) {
    if (testName) {
      if (test.name !== testName) continue
    }
    const { result, name, err } = await testDecryptVector(test)
    if (result) {
      console.log({ name, result })
    } else {
      if (err && notSupportedDecryptMessages.includes(err.message)) {
        console.log({ name, result: `Not supported: ${err.message}` })
        continue
      }
      console.log({ name, result, err })
    }
    if (!result) {
      failureCount += 1
      if (!tolerateFailures) return failureCount
      tolerateFailures--
    }
  }
  return failureCount
}

export async function integrationEncryptTestVectors (manifestFile: string, keyFile: string, decryptOracle: string, tolerateFailures: number = 0, testName?: string) {
  const decryptOracleUrl = new URL(decryptOracle)
  const tests = await getEncryptTestVectorIterator(manifestFile, keyFile)
  let failureCount = 0
  for (const test of tests) {
    if (testName) {
      if (test.name !== testName) continue
    }
    const { result, name, err } = await testEncryptVector(test, decryptOracleUrl)
    if (result) {
      console.log({ name, result })
    } else {
      if (err && notSupportedEncryptMessages.includes(err.message)) {
        console.log({ name, result: `Not supported: ${err.message}` })
        continue
      }
      console.log({ name, result, err })
    }
    if (!result) {
      failureCount += 1
      if (!tolerateFailures) return failureCount
      tolerateFailures--
    }
  }
  return failureCount
}

interface TestVectorResults {
  name: string,
  result: boolean,
  err?: Error
}
