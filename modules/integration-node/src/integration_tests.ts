// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  TestVectorInfo,
  TestVectorResult,
  parseIntegrationTestVectorsToTestVectorIterator,
  PositiveTestVectorInfo,
} from '@aws-crypto/integration-vectors'
import {
  EncryptTestVectorInfo,
  getEncryptTestVectorIterator,
} from './get_encrypt_test_iterator'
import {
  decryptMaterialsManagerNode,
  encryptMaterialsManagerNode,
} from './decrypt_materials_manager_node'
import {
  buildClient,
  CommitmentPolicy,
  MessageHeader,
  needs,
  DecryptOutput,
} from '@aws-crypto/client-node'
import { URL } from 'url'
import got from 'got'
import streamToPromise from 'stream-to-promise'
const { encrypt, decrypt, decryptUnsignedMessageStream } = buildClient(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)
import * as stream from 'stream'
import * as util from 'util'
const pipeline = util.promisify(stream.pipeline)

const notSupportedEncryptMessages = [
  'frameLength out of bounds: 0 > frameLength >= 4294967295',
  'Not supported at this time.',
  'Negative Integration Tests are not supported for EncryptTests',
]

const notSupportedDecryptMessages = ['Not supported at this time.']

async function runDecryption(
  testVectorInfo: TestVectorInfo
): Promise<DecryptOutput> {
  const cmm = decryptMaterialsManagerNode(testVectorInfo.keysInfo)
  if (testVectorInfo.decryptionMethod == 'streaming-unsigned-only') {
    const plaintext: Buffer[] = []
    let messageHeader: MessageHeader | false = false
    // This ignores the return value, but we will either fail and throw an error
    // or retrieve the header/plaintext as a side-effect.
    await pipeline(
      await testVectorInfo.cipherStream(),
      decryptUnsignedMessageStream(cmm)
        .once('MessageHeader', (header: MessageHeader) => {
          messageHeader = header
        })
        .on('data', (chunk: Buffer) => plaintext.push(chunk)),
      // This is necessary to actually make the data flow and populate the plaintext
      new stream.PassThrough()
    )

    needs(messageHeader, 'Unknown format')

    return {
      plaintext: Buffer.concat(plaintext),
      messageHeader,
    }
  } else {
    return await decrypt(cmm, await testVectorInfo.cipherStream(), {})
  }
}

// This is only viable for small streams, if we start get get larger streams, a stream equality should get written
export async function testDecryptVector(
  testVectorInfo: TestVectorInfo
): Promise<TestVectorResult> {
  if ('plainTextStream' in testVectorInfo) {
    return testPositiveDecryptVector(testVectorInfo)
  }
  // Negative Decryption Tests
  try {
    await runDecryption(testVectorInfo)
  } catch (err) {
    return { result: true, name: testVectorInfo.name }
  }
  return {
    result: false,
    name: testVectorInfo.name,
    err: new Error(
      `Should have failed with ${testVectorInfo.errorDescription} but decryption succeeded`
    ),
  }
}

async function testPositiveDecryptVector(
  testVectorInfo: PositiveTestVectorInfo
): Promise<TestVectorResult> {
  const knownGood = await streamToPromise(
    await testVectorInfo.plainTextStream()
  )
  try {
    const { plaintext } = await runDecryption(testVectorInfo)
    if (knownGood.equals(plaintext)) {
      return { result: true, name: testVectorInfo.name }
    }
    // noinspection ExceptionCaughtLocallyJS
    throw new Error('Decrypted Plaintext did not match expected plaintext')
  } catch (err) {
    return { result: false, name: testVectorInfo.name, err }
  }
}

// This is only viable for small streams, if we start get get larger streams, an stream equality should get written
export async function testEncryptVector(
  { name, keysInfo, encryptOp, plainTextData }: EncryptTestVectorInfo,
  decryptOracle: string
): Promise<TestVectorResult> {
  try {
    const cmm = encryptMaterialsManagerNode(keysInfo)
    const { result: encryptResult } = await encrypt(
      cmm,
      plainTextData,
      encryptOp
    )

    const decryptResponse = await got.post(decryptOracle, {
      headers: {
        'Content-Type': 'application/octet-stream',
        Accept: 'application/octet-stream',
      },
      body: encryptResult,
      responseType: 'buffer',
    })
    needs(decryptResponse.statusCode === 200, 'decrypt failure')
    const { body } = decryptResponse
    const result = plainTextData.equals(body)
    return { result, name }
  } catch (err) {
    return { result: false, name, err }
  }
}

function handleTestResults(
  { name, result, err }: TestVectorResult,
  notSupportedMessages: string[]
) {
  if (result) {
    console.log({ name, result })
    return true
  } else {
    if (err && notSupportedMessages.includes(err.message)) {
      console.log({ name, result: `Not supported: ${err.message}` })
      return true
    }
    console.log({ name, result, err })
    return false
  }
}

export async function integrationDecryptTestVectors(
  vectorFile: string,
  tolerateFailures = 0,
  testName?: string,
  concurrency = 1
): Promise<number> {
  const tests = await parseIntegrationTestVectorsToTestVectorIterator(
    vectorFile
  )

  return parallelTests(concurrency, tolerateFailures, runTest, tests)

  async function runTest(test: TestVectorInfo): Promise<boolean> {
    if (testName) {
      if (test.name !== testName) return true
    }
    return handleTestResults(
      await testDecryptVector(test),
      notSupportedDecryptMessages
    )
  }
}

export async function integrationEncryptTestVectors(
  manifestFile: string,
  keyFile: string,
  decryptOracle: string,
  tolerateFailures = 0,
  testName?: string,
  concurrency = 1
): Promise<number> {
  const decryptOracleUrl = new URL(decryptOracle).toString()
  const tests = await getEncryptTestVectorIterator(manifestFile, keyFile)

  return parallelTests(concurrency, tolerateFailures, runTest, tests)

  async function runTest(test: EncryptTestVectorInfo): Promise<boolean> {
    if (testName) {
      if (test.name !== testName) return true
    }
    return handleTestResults(
      await testEncryptVector(test, decryptOracleUrl),
      notSupportedEncryptMessages
    )
  }
}

async function parallelTests<
  Test extends EncryptTestVectorInfo | TestVectorInfo,
  work extends (test: Test) => Promise<boolean>
>(
  max: number,
  tolerateFailures: number,
  runTest: work,
  tests: IterableIterator<Test>
) {
  let _resolve: (failureCount: number) => void
  const queue = new Set<Promise<void>>()
  let failureCount = 0

  return new Promise<number>((resolve) => {
    _resolve = resolve
    enqueue()
  })

  function enqueue(): void {
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
