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
  getTestVectorIterator
} from './get_test_iterator'
import { decryptMaterialsManagerNode } from './decrypt_materials_manager_node'
import { decrypt } from '@aws-crypto/client-node'

// This is only viable for small streams, if we start get get larger streams, an stream equality should get written
export async function testVector ({ name, keysInfo, plainTextStream, cipherStream }: TestVectorInfo): Promise<TestVectorResults> {
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

export async function integrationTestVectors (vectorFile: string, tolerateFailures: number = 0, testName?: string) {
  const tests = await getTestVectorIterator(vectorFile)
  let failureCount = 0
  for (const test of tests) {
    if (testName) {
      if (test.name !== testName) continue
    }
    const { result, name, err } = await testVector(test)
    if (result) {
      console.log({ name, result })
    } else {
      if (err && err.message === 'Not supported at this time.') {
        console.log({ name, result: 'Not supported at this time.' })
        continue
      }
      console.log({ name, result, err })
    }
    if (!result) {
      failureCount += 1
      if (!tolerateFailures) return process.exit(failureCount)
      tolerateFailures--
    }
  }
  return process.exit(failureCount)
}

interface TestVectorResults {
  name: string,
  result: boolean,
  err?: Error
}
