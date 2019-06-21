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
   * Access to kms:GenerateDataKey is required for the generatorKeyId.
   */
  const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

  /* The KMS keyring must be configured with the desired CMKs */
  const keyring = new KmsKeyringNode({ generatorKeyId })

  /* Encryption context is a *very* powerful tool for controlling and managing access.
   * It is ***not*** secret!
   * Remember encrypted data is opaque,
   * encryption context is how a reader
   * asserts things that must be true about the encrypted data.
   * Just because you can decrypt something
   * does not mean it is what you expect.
   * If you are are only expecting data with an from 'us-west-2'
   * the `origin` can be used to identify a malicious actor.
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
      * So it is best to make sure that all the values that you expect exist as opposed to the reverse.
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
