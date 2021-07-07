// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* This is a simple example of configuring a fallback
 * for the AWS Encryption SDK for Javascript
 * in a browser.
 */

import {
  RawAesWrappingSuiteIdentifier,
  RawAesKeyringWebCrypto,
  CommitmentPolicy,
  buildClient,
  synchronousRandomValues,
  configureFallback,
  AlgorithmSuiteIdentifier,
} from '@aws-crypto/client-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'

/* This builds the client with the FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy.
 * This is because the current version of `msrcrypto`
 * does not support `HKDF`.
 * The default commitment policy is `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`
 * if you build the client with `buildClient()`.
 */
const { encrypt, decrypt } = buildClient(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)
/* In this example we use the JavaScript implementation
 * of WebCrypto from MSRCrypto
 * and configure it as a fallback for the AWS Encryption SDK.
 * The implementation will only be used if it is needed.
 * The AWS Encryption SDK will _always_ prefer the native browser implementation.
 * The msrCrypto source file is included as a script tag in the HTML file.
 * See fallback.html
 */
// @ts-ignore
import { subtle } from './msrcrypto'
configureFallback(subtle as SubtleCrypto).catch((e) => {
  throw e
})

/* This is done to facilitate testing. */
export async function testFallback() {
  /* You need to specify a name
   * and a namespace for raw encryption key providers.
   * The name and namespace that you use in the decryption keyring *must* be an exact,
   * *case-sensitive* match for the name and namespace in the encryption keyring.
   */
  const keyName = 'aes-name'
  const keyNamespace = 'aes-namespace'

  /* The wrapping suite defines the AES-GCM algorithm suite to use. */
  const wrappingSuite =
    RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING

  // Get your plaintext master key from wherever you store it.
  const unencryptedMasterKey = synchronousRandomValues(32)

  /* Import the plaintext master key into a WebCrypto CryptoKey. */
  const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(
    unencryptedMasterKey,
    wrappingSuite
  )

  /* Configure the Raw AES keyring. */
  const keyring = new RawAesKeyringWebCrypto({
    keyName,
    keyNamespace,
    wrappingSuite,
    masterKey,
  })

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

  /* Find data to encrypt. */
  const plainText = new Uint8Array([1, 2, 3, 4, 5])

  /* Encrypt the data. */
  const { result } = await encrypt(keyring, plainText, {
    encryptionContext: context,
    suiteId: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16,
  })

  /* Log the plain text
   * only for testing and to show that it works.
   */
  console.log('plainText:', plainText)
  document.body.insertAdjacentHTML(
    'beforeend',
    `<p>plainText:<p>${plainText}</p> </p>`
  )

  /* Log the base64-encoded result
   * so that you can try decrypting it with another AWS Encryption SDK implementation.
   */
  const resultBase64 = toBase64(result)
  console.log(resultBase64)
  document.body.insertAdjacentHTML('beforeend', `<p>${resultBase64}</p>`)

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

  /* Log the clear message
   * only for testing and to show that it works.
   */
  console.log(plaintext)
  document.body.insertAdjacentHTML(
    'beforeend',
    `<p>plainText:<p>${plaintext}</p> </p>`
  )

  /* Return the values to make testing easy. */
  return { plainText, plaintext }
}
