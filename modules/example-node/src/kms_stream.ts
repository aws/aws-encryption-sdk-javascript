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

import { KmsKeyringNode } from '@aws-crypto/kms-keyring-node'
import { encryptStream } from '@aws-crypto/encrypt-node'
import {
  decryptStream,
  MessageHeader // eslint-disable-line no-unused-vars
} from '@aws-crypto/decrypt-node'
import { finished } from 'stream'
import { createReadStream, createWriteStream } from 'fs'
import { promisify } from 'util'
const finishedAsync = promisify(finished)

export async function kmsStreamTest () {
  /* A KMS CMK to generate the data key is required.
   * Access to KMS generateDataKey is required for the generatorKeyId.
   */
  const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

  /* The KMS Keyring must be configured with the desired CMK's */
  const keyring = new KmsKeyringNode({ generatorKeyId })

  /* Encryption Context is a *very* powerful tool for controlling and managing access.
   * It is ***not*** secret!
   * Remember encrypted data is opaque, encryption context will help your run time checking.
   * Just because you have decrypted a JSON file, and it successfully parsed,
   * does not mean it is the intended JSON file.
   */
  const context = {
    stage: 'demo',
    purpose: 'simple demonstration app',
    origin: 'us-west-2'
  }

  /* Create a simple pipeline to encrypt the package.json for this project. */
  const stream = createReadStream('./package.json')
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
    .pipe(createWriteStream('./package.json.decrypt'))

  return finishedAsync(stream)
}
