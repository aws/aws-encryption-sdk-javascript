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

import { encrypt } from '@aws-crypto/encrypt-browser'
import { decrypt } from '@aws-crypto/decrypt-browser'
import {
  KmsKeyringBrowser,
  KMS,
  getClient
} from '@aws-crypto/kms-keyring-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'

/* This is injected by webpack.
 * The webpack.DefinePlugin will replace the values when bundling.
 * The credential values are pulled from @aws-sdk/credential-provider-node
 * Use any method you like to get credentials into the browser.
 * See kms.webpack.config
 */
declare const AWS_CREDENTIALS: {accessKeyId: string, secretAccessKey:string }

;(async function kmsSimpleExample () {
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

  /* The KMS Keyring must be configured with the desired CMK's */
  const keyring = new KmsKeyringBrowser({ clientProvider, generatorKeyId, keyIds })

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

  /* I need something to encrypt. */
  const plainText = new Uint8Array([1, 2, 3, 4, 5])

  /* Encrypt the data. */
  const { cipherMessage } = await encrypt(keyring, plainText, { encryptionContext: context })

  /* Log the plain text. */
  console.log('plainText:', plainText)
  document.write('</br>plainText:' + plainText + '</br>')

  /* In case you want to check compatibility, I log the cipher text. */
  const cipherMessageBase64 = toBase64(cipherMessage)
  console.log(cipherMessageBase64)
  document.write(cipherMessageBase64)

  const { clearMessage, messageHeader } = await decrypt(keyring, cipherMessage)

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

  /* Log the clear message. */
  document.write('</br>Decrypted:' + clearMessage)
  console.log(clearMessage)
})()
