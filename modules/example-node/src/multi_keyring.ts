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

/* This is a simple example of using a multi-keyring KMS keyring
 * to combine a KMS keyring and a raw AES keyring
 * to encrypt and decrypt using the AWS Encryption SDK for Javascript in Node.js.
 */

import { MultiKeyringNode, KmsKeyringNode, RawAesKeyringNode, RawAesWrappingSuiteIdentifier, encrypt, decrypt } from '@aws-crypto/client-node'
import { randomBytes } from 'crypto'

export async function multiKeyringTest () {
  /* A KMS CMK is required to generate the data key.
   * You need kms:GenerateDataKey permission on the CMK in generatorKeyId.
   */
  const generatorKeyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

  /* Adding alternate KMS keys that can decrypt.
   * Access to kms:Encrypt is required for every CMK in keyIds.
   * You might list several keys in different AWS Regions.
   * This allows you to decrypt the data in any of the represented Regions.
   * In this example, I am using the same CMK.
   * This is *only* to demonstrate how the CMK ARNs are configured.
   */
  const keyIds = ['arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f']

  /* The KMS keyring must be configured with the desired CMKs */
  const kmsKeyring = new KmsKeyringNode({ generatorKeyId, keyIds })

  /* You need to specify a name
   * and a namespace for raw encryption key providers.
   * The name and namespace that you use in the decryption keyring *must* be an exact,
   * *case-sensitive* match for the name and namespace in the encryption keyring.
   */
  const keyName = 'aes-name'
  const keyNamespace = 'aes-namespace'
  /* The wrapping suite defines the AES-GCM algorithm suite to use. */
  const wrappingSuite = RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING
  // Get your plaintext master key from wherever you store it.
  const unencryptedMasterKey = randomBytes(32)

  /* Configure the Raw AES Keyring. */
  const aesKeyring = new RawAesKeyringNode({ keyName, keyNamespace, unencryptedMasterKey, wrappingSuite })

  /* Combine the two keyrings with a MultiKeyring. */
  const keyring = new MultiKeyringNode({ generator: kmsKeyring, children: [ aesKeyring ] })

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

  /* Find data to encrypt.  A simple string. */
  const cleartext = 'asdf'

  /* Encrypt the data. */
  const { ciphertext } = await encrypt(keyring, cleartext, { encryptionContext: context })

  /* Decrypt the data.
   * This decrypt call could be done with **any** of the 3 keyrings.
   * Here we use the multi-keyring, but
   * decrypt(kmsKeyring, ciphertext)
   * decrypt(aesKeyring, ciphertext)
   * would both work as well.
   */
  const { plaintext, messageHeader } = await decrypt(keyring, ciphertext)

  /* Grab the encryption context so you can verify it. */
  const { encryptionContext } = messageHeader

  /* Verify the encryption context.
   * If you use an algorithm suite with signing,
   * the Encryption SDK adds a name-value pair to the encryption context that contains the public key.
   * Because the encryption context might contain additional key-value pairs,
   * do not add a test that requires that all key-value pairs match.
   * Instead, verify that the key-value pairs you expect match.
   */
  Object
    .entries(context)
    .forEach(([key, value]) => {
      if (encryptionContext[key] !== value) throw new Error('Encryption Context does not match expected values')
    })

  /* Return the values so the code can be tested. */
  return { plaintext, ciphertext, cleartext, messageHeader }
}
