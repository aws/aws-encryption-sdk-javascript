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

/* This is a simple example of using a KMS Keyring
 * to encrypt and decrypt using the AWS Encryption SDK for Javascript in a browser.
 */

import {
  KmsKeyringBrowser,
  KMS,
  getClient,
  encrypt,
  decrypt
} from '@aws-crypto/client-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'

/* This is injected by webpack.
 * The webpack.DefinePlugin will replace the values when bundling.
 * The credential values are pulled from @aws-sdk/credential-provider-node
 * Use any method you like to get credentials into the browser.
 * See kms.webpack.config
 */
declare const AWS_CREDENTIALS: {accessKeyId: string, secretAccessKey:string }

;(async function kmsSimpleExample () {
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

  /* Need a client provider that will inject correct credentials.
   * The credentials here are injected by webpack from your environment bundle is created
   * The credential values are pulled using @aws-sdk/credential-provider-node.
   * See kms.webpack.config
   * You should inject your credential into the browser in a secure manner,
   * that works with your application.
   */
  const { accessKeyId, secretAccessKey } = AWS_CREDENTIALS

  /* getClient takes a KMS client constructor
   * and optional configuration values.
   * The credentials can be injected here,
   * because browser do not have a standard credential discover process the way Node.js does.
   */
  const clientProvider = getClient(KMS, {
    credentials: {
      accessKeyId,
      secretAccessKey
    }
  })

  /* The KMS keyring must be configured with the desired CMKs */
  const keyring = new KmsKeyringBrowser({ clientProvider, generatorKeyId, keyIds })

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

  /* Find data to encrypt. */
  const plainText = new Uint8Array([1, 2, 3, 4, 5])

  /* Encrypt the data. */
  const { cipherMessage } = await encrypt(keyring, plainText, { encryptionContext: context })

  /* Log the plain text
   * only for testing and to show that it works.
   */
  console.log('plainText:', plainText)
  document.write('</br>plainText:' + plainText + '</br>')

  /* Log the base64-encoded ciphertext
   * so that you can try decrypting it with another AWS Encryption SDK implementation.
   */
  const cipherMessageBase64 = toBase64(cipherMessage)
  console.log(cipherMessageBase64)
  document.write(cipherMessageBase64)

  const { clearMessage, messageHeader } = await decrypt(keyring, cipherMessage)

  /* Grab the encryption context so you can verify it. */
  const { encryptionContext } = messageHeader

  /* Verify the encryption context.
   * If you use an algorithm suite with signing,
   * the SDK adds a name-value pair to the encryption context that contains the public key.
   * Because the encryption context might contain additional key-value pairs,
   * do not add a test that requires that all key-value pairs match.
   * Instead, verify that the key-value pairs you expect match.
   */
  Object
    .entries(context)
    .forEach(([key, value]) => {
      if (encryptionContext[key] !== value) throw new Error('Encryption Context does not match expected values')
    })

  /* Log the clear message
   * only for testing and to show that it works.
   */
  document.write('</br>Decrypted:' + clearMessage)
  console.log(clearMessage)
})()
