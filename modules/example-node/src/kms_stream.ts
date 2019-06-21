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
  KmsKeyringNode,
  decryptStream,
  encryptStream,
  MessageHeader // eslint-disable-line no-unused-vars
} from '@aws-crypto/client-node'

import { finished } from 'stream'
import { createReadStream } from 'fs'
import { promisify } from 'util'
const finishedAsync = promisify(finished)

export async function kmsStreamTest (filename: string) {
  /* A KMS CMK is required to generate the data key.
   * You need kms:GenerateDataKey permission on the CMK in generatorKeyId.
   */
  const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

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
    origin: 'us-west-2'
  }

  /* Create a simple pipeline to encrypt the package.json for this project. */
  const stream = createReadStream(filename)
    .pipe(encryptStream(keyring, { context }))
    .pipe(decryptStream(new KmsKeyringNode({ discovery: true })))
    .on('MessageHeader', ({ encryptionContext }: MessageHeader) => {
      /* Verify the encryption context.
      * Depending on the Algorithm Suite, the `encryptionContext` _may_ contain additional values.
      * In Signing Algorithm Suites the public verification key is serialized into the `encryptionContext`.
      * Because the encryption context might contain additional key-value pairs,
      * do not add a test that requires that all key-value pairs match.
      * Instead, verify that the key-value pairs you expect match.
      */
      Object
        .entries(context)
        .forEach(([key, value]) => {
          if (encryptionContext[key] !== value) throw new Error('Encryption Context does not match expected values')
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
