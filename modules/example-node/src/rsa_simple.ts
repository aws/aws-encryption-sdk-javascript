// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  RawRsaKeyringNode,
  buildClient,
  CommitmentPolicy,
} from '@aws-crypto/client-node'
import { generateKeyPair } from 'crypto'
import { promisify } from 'util'
const generateKeyPairAsync = promisify(generateKeyPair)

/* This builds the client with the REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy,
 * which enforces that this client only encrypts using committing algorithm suites
 * and enforces that this client
 * will only decrypt encrypted messages
 * that were created with a committing algorithm suite.
 * This is the default commitment policy
 * if you build the client with `buildClient()`.
 */
const { encrypt, decrypt } = buildClient(
  CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)

/**
 * This function is an example of using the RsaKeyringNode
 * to encrypt and decrypt a simple string
 */
export async function rsaTest() {
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

  /* Find data to encrypt.  A simple string. */
  const cleartext = 'asdf'

  /* Encrypt the data. */
  const { result } = await encrypt(keyring, cleartext, {
    encryptionContext: context,
  })
  /* Decrypt the data. */
  const { plaintext, messageHeader } = await decrypt(keyring, result)

  /* Grab the encryption context so you can verify it. */
  const { encryptionContext } = messageHeader

  /* Verify the encryption context.
   * If you use an algorithm suite with signing,
   * the Encryption SDK adds a name-value pair to the encryption context that contains the public key.
   * Because the encryption context might contain additional key-value pairs,
   * do not add a test that requires that all key-value pairs match.
   * Instead, verify that the key-value pairs you expect match.
   */
  Object.entries(context).forEach(([key, value]) => {
    if (encryptionContext[key] !== value)
      throw new Error('Encryption Context does not match expected values')
  })

  /* Return the values so the code can be tested. */
  return { plaintext, result, cleartext }
}

/**
 * This is a helper function to generate an RSA key pair for testing purposes only.
 */
async function generateRsaKeys() {
  const modulusLength = 3072
  const publicKeyEncoding = { type: 'pkcs1', format: 'pem' }
  const privateKeyEncoding = { type: 'pkcs1', format: 'pem' }
  // @ts-ignore
  return generateKeyPairAsync('rsa', {
    modulusLength,
    publicKeyEncoding,
    privateKeyEncoding,
  })
}
