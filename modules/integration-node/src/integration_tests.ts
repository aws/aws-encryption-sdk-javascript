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

export async function integrationDecryptTestVectors (vectorFile: string, tolerateFailures: number = 0, testName?: string, concurrency: number = 1) {
  const tests = await getDecryptTestVectorIterator(vectorFile)

  return parallelTests(concurrency, tolerateFailures, runTest, tests)

  async function runTest (test: TestVectorInfo): Promise<boolean> {
    if (testName) {
      if (test.name !== testName) return true
    }
    const { result, name, err } = await testDecryptVector(test)
    if (result) {
      console.log({ name, result })
      return true
    } else {
      if (err && notSupportedDecryptMessages.includes(err.message)) {
        console.log({ name, result: `Not supported: ${err.message}` })
        return true
      }
      console.log({ name, result, err })
      return false
    }
  }
}

export async function integrationEncryptTestVectors (manifestFile: string, keyFile: string, decryptOracle: string, tolerateFailures: number = 0, testName?: string, concurrency: number = 1) {
  const decryptOracleUrl = new URL(decryptOracle)
  const tests = await getEncryptTestVectorIterator(manifestFile, keyFile)

  return parallelTests(concurrency, tolerateFailures, runTest, tests)

  async function runTest (test: EncryptTestVectorInfo): Promise<boolean> {
    if (testName) {
      if (test.name !== testName) return true
    }
    const { result, name, err } = await testEncryptVector(test, decryptOracleUrl)
    if (result) {
      console.log({ name, result })
      return true
    } else {
      if (err && notSupportedEncryptMessages.includes(err.message)) {
        console.log({ name, result: `Not supported: ${err.message}` })
        return true
      }
      console.log({ name, result, err })
      return false
    }
  }
}

async function parallelTests<
  Test extends EncryptTestVectorInfo|TestVectorInfo,
  work extends (test: Test) => Promise<boolean>
>(max: number, tolerateFailures: number, runTest: work, tests: IterableIterator<Test>) {
  let _resolve: (failureCount: number) => void
  const queue = new Set<Promise<void>>()
  let failureCount = 0

  return new Promise<number>((resolve) => {
    _resolve = resolve
    enqueue()
  })

  function enqueue (): void {
    /* If there are more failures than I am willing to tolerate, stop. */
    if (failureCount > tolerateFailures) return _resolve(failureCount)
    /* Do not over-fill the queue! */
    if (queue.size > max) return

    const { value, done } = tests.next()
    /* There is an edge here,
     * you _could_ return a value *and* be done.
     * Most iterators don't but in this case
     * we just process the value and ask for another.
     * Which will return done as true again.
     */
    if (!value && done) return _resolve(failureCount)

    /* I need to define the work to be enqueue
     * and a way to dequeue this work when complete.
     * A Set of promises works nicely.
     * Hold the variable here
     * put it in the Set, take it out, and Bob's your uncle.
     */
    const work: Promise<void> = runTest(value)
      .then((pass: boolean) => {
        if (!pass) failureCount += 1
      })
      /* If there is some unknown error,
       * it's just an error...
       * Treat it like a test failure.
       */
      .catch((err) => {
        console.log(err)
        failureCount += 1
      })
      .then(() => {
        /* Dequeue this work. */
        queue.delete(work)
        /* More to eat? */
        enqueue()
      })

    /* Enqueue this work */
    queue.add(work)

    /* Fill the queue.
     * The over-fill check above protects me.
     * Sure, it is possible to exceed the stack depth.
     * If you are trying to run ~10K tests in parallel
     * on a system where that is actually faster,
     * I want to talk to you.
     * It is true that node can be configured to process
     * > 10K HTTP requests no problem,
     * but even the decrypt tests require that you first
     * encrypt something locally before making the http call.
     */
    enqueue()
  }
}

interface TestVectorResults {
  name: string,
  result: boolean,
  err?: Error
}
