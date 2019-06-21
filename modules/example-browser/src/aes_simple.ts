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

/* This is a simple example of using a raw AES keyring
 * to encrypt and decrypt using the AWS Encryption SDK for Javascript
 * in a browser.
 */

import {
  RawAesWrappingSuiteIdentifier,
  RawAesKeyringWebCrypto,
  encrypt,
  decrypt,
  synchronousRandomValues
} from '@aws-crypto/client-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'

  ;(async function testAES () {
  /* You need to specify a name
   * and a namespace for raw encryption key providers.
   * The name and namespace that you use in the decryption keyring *must* be an exact,
   * *case-sensitive* match for the name and namespace in the encryption keyring.
   */
  const keyName = 'aes-name'
  const keyNamespace = 'aes-namespace'

  /* The wrapping suite defines the AES-GCM algorithm suite to use. */
  const wrappingSuite = RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING

  // Get your unencrypted master key from wherever you store it.
  const unencryptedMasterKey = synchronousRandomValues(32)

  /* Import the plaintext master key into a WebCrypto CryptoKey. */
  const masterKey = await RawAesKeyringWebCrypto.importCryptoKey(unencryptedMasterKey, wrappingSuite)

  /* Configure the Raw AES keyring. */
  const keyring = new RawAesKeyringWebCrypto({ keyName, keyNamespace, wrappingSuite, masterKey })

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

  /* I need something to encrypt. */
  const plainText = new Uint8Array([1, 2, 3, 4, 5])

  /* Encrypt the data. */
  const { cipherMessage } = await encrypt(keyring, plainText, { encryptionContext: context })

  /* Log the plain text
   * only for testing and to show that it works.
   */
  console.log('plainText:', plainText)
  document.write('</br>plainText:' + plainText + '</br>')

  /* Log the ciphertext so you can copy it
   * and check compatibility with another another implementation of the AWS Encryption SDK.
   */
  const cipherMessageBase64 = toBase64(cipherMessage)
  console.log(cipherMessageBase64)
  document.write(cipherMessageBase64)

  const { clearMessage, messageHeader } = await decrypt(keyring, cipherMessage)

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

  /* Log the clear message
   * only for testing and to show that it works.
   */
  document.write('</br>clearMessage:' + clearMessage)
  console.log(clearMessage)
})()
