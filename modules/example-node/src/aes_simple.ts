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

import { RawAesKeyringNode, encrypt, decrypt, RawAesWrappingSuiteIdentifier } from '@aws-crypto/client-node'
import { randomBytes } from 'crypto'

/**
 * This function is an example of using the RawAesKeyringNode
 * to encrypt and decrypt a simple string
 */
export async function aesTest () {
  /* You need to specify a name
   * and a namespace for raw encryption key providers.
   * The name and namespace that you use in the decryption keyring *must* be an exact,
   * *case-sensitive* match for the name and namespace in the encryption keyring.
   */
  const keyName = 'aes-name'
  const keyNamespace = 'aes-namespace'

  /* The wrapping suite defines the AES-GCM algorithm suite to use. */
  const wrappingSuite = RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING

  // You should get your unencrypted master key from wherever you store it.
  const unencryptedMasterKey = randomBytes(32)

  /* Configure the Raw AES keyring. */
  const keyring = new RawAesKeyringNode({ keyName, keyNamespace, unencryptedMasterKey, wrappingSuite })

  /* Encryption context is a *very* powerful tool for controlling and managing access.
   * It is ***not*** secret!
   * Remember encrypted data is opaque,
   * encryption context is how a reader
   * asserts things that must be true about the encrypted data.
   * Just because you can decrypt something
   * does not mean it is what you expect.
   * If you are are only expecting data with an from 'us-west-2'
   * the `origin` can be used to identify a malicious actor.
   * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
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

  /* Grab the encryption context so you can verify it. */
  const { encryptionContext } = messageHeader

  /* Verify the encryption context.
   * Depending on the algorithm suite, the `encryptionContext` _may_ contain additional values.
   * If you use an algorithm suite with signing,
   * the SDK adds a name-value pair to the encryption context that contains the public key.
   * Because the encryption context might contain additional key-value pairs,
   * do not add a test that requires that all key-value pairs match.
   * Instead verify that the key-value pairs you expect match.
   */
  Object
    .entries(context)
    .forEach(([key, value]) => {
      if (encryptionContext[key] !== value) throw new Error('Encryption Context does not match expected values')
    })

  /* Return the values so I can manage this code with tests. */
  return { plaintext, ciphertext, cleartext }
}
