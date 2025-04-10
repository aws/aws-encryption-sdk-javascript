// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  TestVectorInfo,
  TestVectorResult,
  parseIntegrationTestVectorsToTestVectorIterator,
  PositiveTestVectorInfo,
  DecryptManifestList,
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
  getCompatibleCommitmentPolicy,
} from '@aws-crypto/client-node'
import { version } from './version'
import { URL } from 'url'
import got from 'got'
import streamToPromise from 'stream-to-promise'
import { ZipFile } from 'yazl'
import { createWriteStream } from 'fs'
import { v4 } from 'uuid'
import * as stream from 'stream'
import * as util from 'util'
import {
  DECRYPT_MANIFEST_CLIENT_NAME,
  DECRYPT_MANIFEST_TYPE,
  KEYS_MANIFEST_NAME_FILENAME,
  MANIFEST_CIPHERTEXT_PATH,
  MANIFEST_NAME_FILENAME,
  MANIFEST_PLAINTEXT_PATH,
  MANIFEST_URI_PREFIX,
} from './constants'
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
  const { decrypt, decryptUnsignedMessageStream } = buildClient(
    CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
  )
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

interface ProcessEncryptResults {
  handleEncryptResult: HandleEncryptResult
  // We need to have a done step to close the ZipFile.
  done(): void
  // The handleEncryptResult needs the ZipFile
  // so that it can add ciphertexts and tests.
  // But when we set up the encrypt manifest,
  // we create plaintext files and have the keys manifest.
  // This is a quick and dirty way to share the ZipFile
  // between these two places.
  manifestZip?: ZipFile
}

interface HandleEncryptResult {
  (encryptResult: Buffer, info: EncryptTestVectorInfo): Promise<boolean>
}

export async function testEncryptVector(
  info: EncryptTestVectorInfo,
  handleEncryptResult: HandleEncryptResult
): Promise<TestVectorResult> {
  const { name, keysInfo, encryptOp, plainTextData } = info
  const commitmentPolicy = getCompatibleCommitmentPolicy(encryptOp.suiteId)
  const { encrypt } = buildClient(commitmentPolicy)
  try {
    const cmm = encryptMaterialsManagerNode(keysInfo)
    const { result: encryptResult } = await encrypt(
      cmm,
      plainTextData,
      encryptOp
    )

    const result = await handleEncryptResult(encryptResult, info)
    return { result, name }
  } catch (err) {
    return { result: false, name, err }
  }
}

// This isolates the logic on how to do both.
// Right now we only have 2 ways to handle results
// so this seems reasonable.
function composeEncryptResults(
  decryptOracle?: string,
  decryptManifest?: string
): ProcessEncryptResults {
  if (!!decryptOracle && !!decryptManifest) {
    const oracle = decryptOracleEncryptResults(decryptOracle)
    const manifest = decryptionManifestEncryptResults(decryptManifest)

    return {
      done() {
        manifest.done()
        oracle.done()
      },

      async handleEncryptResult(
        encryptResult: Buffer,
        info: EncryptTestVectorInfo
      ): Promise<boolean> {
        return Promise.all([
          oracle.handleEncryptResult(encryptResult, info),
          manifest.handleEncryptResult(encryptResult, info),
        ]).then((results) => {
          const [oracleResult, manifestResult] = results
          return oracleResult && manifestResult
        })
      },
      manifestZip: manifest.manifestZip,
    }
  } else if (decryptOracle) {
    return decryptOracleEncryptResults(decryptOracle)
  } else if (decryptManifest) {
    return decryptionManifestEncryptResults(decryptManifest)
  }
  needs(false, 'unsupported')
}

function decryptOracleEncryptResults(
  decryptOracle: string
): ProcessEncryptResults {
  const decryptOracleUrl = new URL(decryptOracle).toString()
  return {
    handleEncryptResult,
    // There is nothing to do when the oracle is done
    // since nothing is saved.
    done: () => {
      return null
    },
  }

  async function handleEncryptResult(
    encryptResult: Buffer,
    info: EncryptTestVectorInfo
  ): Promise<boolean> {
    const decryptResponse = await got.post(decryptOracleUrl, {
      headers: {
        'Content-Type': 'application/octet-stream',
        Accept: 'application/octet-stream',
      },
      body: encryptResult,
      responseType: 'buffer',
    })
    needs(decryptResponse.statusCode === 200, 'decrypt failure')
    const { body } = decryptResponse
    // This is only viable for small streams,
    // if we start get get larger streams,
    // a stream equality should get written
    return info.plainTextData.equals(body)
  }
}

function decryptionManifestEncryptResults(
  manifestPath: string
): ProcessEncryptResults {
  const manifestZip = new ZipFile()
  const manifest: DecryptManifestList = {
    manifest: {
      type: `${DECRYPT_MANIFEST_TYPE}`,
      version: 2,
    },
    client: {
      name: `${DECRYPT_MANIFEST_CLIENT_NAME}`,
      version,
    },
    keys: `${MANIFEST_URI_PREFIX}${KEYS_MANIFEST_NAME_FILENAME}`,
    tests: {},
  }
  manifestZip.outputStream.pipe(createWriteStream(manifestPath))

  return {
    handleEncryptResult,
    done: () => {
      // All the tests have completed,
      // so we write the manifest,
      // as close the zip file.
      manifestZip.addBuffer(
        Buffer.from(JSON.stringify(manifest)),
        `${MANIFEST_NAME_FILENAME}`
      )
      manifestZip.end()
    },
    manifestZip,
  }

  async function handleEncryptResult(
    encryptResult: Buffer,
    info: EncryptTestVectorInfo
  ): Promise<boolean> {
    const testName = v4()

    manifestZip.addBuffer(
      encryptResult,
      `${MANIFEST_CIPHERTEXT_PATH}${testName}`
    )

    manifest.tests[testName] = {
      description: `Decrypt vector from ${info.name}`,
      ciphertext: `${MANIFEST_URI_PREFIX}${MANIFEST_CIPHERTEXT_PATH}${testName}`,
      'master-keys': info.keysInfo.map((info) => info[0]),
      result: {
        output: {
          plaintext: `${MANIFEST_URI_PREFIX}${MANIFEST_PLAINTEXT_PATH}${info.plaintextName}`,
        },
      },
    }

    // These files are tested on decrypt
    // so there is nothing to test at this point.
    return true
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
  CVE202346809?: boolean,
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

    if (
      !CVE202346809 &&
      test.keysInfo.some(
        ([info, _]) =>
          info.type == 'raw' && info['padding-algorithm'] == 'pkcs1'
      )
    ) {
      return true
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
  decryptOracle?: string,
  decryptManifest?: string,
  tolerateFailures = 0,
  testName?: string,
  concurrency = 1
): Promise<number> {
  needs(
    !!decryptOracle || !!decryptManifest,
    'Need to pass an oracle or manifest path.'
  )

  const { done, handleEncryptResult, manifestZip } = composeEncryptResults(
    decryptOracle,
    decryptManifest
  )

  const tests = await getEncryptTestVectorIterator(
    manifestFile,
    keyFile,
    manifestZip
  )

  return parallelTests(concurrency, tolerateFailures, runTest, tests).then(
    (num) => {
      // Do the output processing here
      done()
      return num
    }
  )

  async function runTest(test: EncryptTestVectorInfo): Promise<boolean> {
    if (testName) {
      if (test.name !== testName) return true
    }
    return handleTestResults(
      await testEncryptVector(test, handleEncryptResult),
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
    if (!value && done) {
      // We are done enqueueing work,
      // but we need to wait until all that work is done
      Promise.all([...queue])
        .then(() => _resolve(failureCount))
        .catch(console.log)
      return
    }
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
