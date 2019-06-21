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

import { RawRsaKeyringNode, encrypt, decrypt } from '@aws-crypto/client-node'

import { generateKeyPair } from 'crypto'
import { promisify } from 'util'
const generateKeyPairAsync = promisify(generateKeyPair)

/**
 * This function is an example of using the RsaKeyringNode
 * to encrypt and decrypt a simple string
 */
export async function rsaTest () {
  /* You need to specify a name
   * and a namespace for raw encryption key providers.
   * The name and namespace that you use in the decryption keyring *must* be an exact,
   * *case-sensitive* match for the name and namespace in the encryption keyring.
   */
  const keyName = 'rsa-name'
  const keyNamespace = 'rsa-namespace'
  // Get your key pairs from wherever you  store them.
  const rsaKey = await generateRsaKeys()

  /* The RSA keyring must be configured with the desired RSA keys
   * If you only want to encrypt, only configure a public key.
   * If you only want to decrypt, only configure a private key.
   */
  const keyring = new RawRsaKeyringNode({ keyName, keyNamespace, rsaKey })

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
   * So it is best to make sure that all the values that you expect exist as opposed to the reverse.
   */
  Object
    .entries(context)
    .forEach(([key, value]) => {
      if (encryptionContext[key] !== value) throw new Error('Encryption Context does not match expected values')
    })

  /* Return the values so I can manage this code with tests. */
  return { plaintext, ciphertext, cleartext }
}

/**
 * This is a helper function to generate an RSA key pair for testing purposes only.
 */
async function generateRsaKeys () {
  const modulusLength = 3072
  const publicKeyEncoding = { type: 'pkcs1', format: 'pem' }
  const privateKeyEncoding = { type: 'pkcs1', format: 'pem' }
  // @ts-ignore
  return generateKeyPairAsync('rsa', {
    modulusLength,
    publicKeyEncoding,
    privateKeyEncoding
  })
}
