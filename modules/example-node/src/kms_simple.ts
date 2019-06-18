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

import { KmsKeyringNode, encrypt, decrypt } from '@aws-crypto/client-node'

export async function kmsSimpleTest () {
  /* A KMS CMK to generate the data key is required.
   * Access to KMS generateDataKey is required for the generatorKeyId.
   */
  const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

  /* Adding Alternate KMS keys that can decrypt.
   * Access to KMS encrypt is required for every CMK in keyIds.
   * Often this used to have a local CMK in multiple regions.
   * In this example, I am using the same CMK.
   * This is *only* to demonstrate how the CMK ARN's are configured.
   */
  const keyIds = ['arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f']

  /* The KMS Keyring must be configured with the desired CMK's */
  const keyring = new KmsKeyringNode({ generatorKeyId, keyIds })

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

  /* I need something to encrypt.  A simple string. */
  const cleartext = 'asdf'

  /* Encrypt the data. */
  const { ciphertext } = await encrypt(keyring, cleartext, { context })

  /* Decrypt the data. */
  const { plaintext, messageHeader } = await decrypt(keyring, ciphertext)

  /* Grab the encryption context so I can verify it. */
  const { encryptionContext } = messageHeader

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

  /* Return the values so I can manage this code with tests. */
  return { plaintext, ciphertext, cleartext, messageHeader }
}
