// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringNode,
  buildClient,
  CommitmentPolicy,
  MessageHeader,
} from '@aws-crypto/client-node'
import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management'

/* This builds the client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy,
 * which enforces that this client only encrypts using committing algorithm suites
 * and enforces that this client
 * will only decrypt encrypted messages
 * that were created with a committing algorithm suite.
 * This is the default commitment policy
 * if you build the client with `buildClient()`.
 */
const { encryptStream, decryptUnsignedMessageStream } = buildClient(
  CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

import { finished } from 'stream'
import { createReadStream } from 'fs'
import { promisify } from 'util'
const finishedAsync = promisify(finished)

export async function kmsStreamTest(filename: string) {
  /* A KMS CMK is required to generate the data key.
   * You need kms:GenerateDataKey permission on the CMK in generatorKeyId.
   */
  const generatorKeyId =
    'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

  /* The KMS keyring must be configured with the desired CMKs */
  const keyring = new KmsKeyringNode({ generatorKeyId })

  /* Encryption context is a *very* powerful tool for controlling and managing access.
   * It is ***not*** secret!
   * Encrypted data is opaque.
   * You can use an encryption context to assert things about the encrypted data.
   * Just because you can decrypt something does not mean it is what you expect.
   * For example, if you are are only expecting data from 'us-west-2',
   * the origin can identify a malicious actor.
   * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
   */
  const context = {
    stage: 'demo',
    purpose: 'simple demonstration app',
    origin: 'us-west-2',
  }

  /* Create a simple pipeline to encrypt the package.json for this project. */
  const stream = createReadStream(filename)
    .pipe(
      encryptStream(keyring, {
        /*
         * Since we are streaming, and assuming that the encryption and decryption contexts
         * are equally trusted, using an unsigned algorithm suite is faster and avoids
         * the possibility of processing plaintext before the signature is verified.
         */
        suiteId:
          AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY,
        encryptionContext: context,
      })
    )
    /*
     * decryptUnsignedMessageStream is recommended when streaming if you don't need
     * digital signatures.
     */
    .pipe(decryptUnsignedMessageStream(new KmsKeyringNode({ discovery: true })))
    .on('MessageHeader', ({ encryptionContext }: MessageHeader) => {
      /* Verify the encryption context.
       * Depending on the Algorithm Suite, the `encryptionContext` _may_ contain additional values.
       * In Signing Algorithm Suites the public verification key is serialized into the `encryptionContext`.
       * Because the encryption context might contain additional key-value pairs,
       * do not add a test that requires that all key-value pairs match.
       * Instead, verify that the key-value pairs you expect match.
       */
      Object.entries(context).forEach(([key, value]) => {
        if (encryptionContext[key] !== value)
          throw new Error('Encryption Context does not match expected values')
      })
    })

  /* This is not strictly speaking part of the example.
   * Streams need a place to drain.
   * To test this code I just accumulate the stream.
   * Then I can return that Buffer and verify.
   * In a real world case you do not want to always buffer the whole stream.
   */
  const buff: Buffer[] = []
  stream.on('data', (chunk: Buffer) => {
    buff.push(chunk)
  })

  await finishedAsync(stream)
  return Buffer.concat(buff)
}
