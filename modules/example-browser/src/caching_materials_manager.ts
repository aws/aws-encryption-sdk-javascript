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
  decrypt,
  WebCryptoCachingMaterialsManager,
  getLocalCryptographicMaterialsCache
} from '@aws-crypto/client-browser'
import { toBase64 } from '@aws-sdk/util-base64-browser'

/* This is injected by webpack.
 * The webpack.DefinePlugin will replace the values when bundling.
 * The credential values are pulled from @aws-sdk/credential-provider-node
 * Use any method you like to get credentials into the browser.
 * See kms.webpack.config
 */
declare const credentials: {accessKeyId: string, secretAccessKey:string, sessionToken:string }

/* This is done to facilitate testing. */
export async function testCachingMaterialsManagerExample () {
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
  const { accessKeyId, secretAccessKey, sessionToken } = credentials

  /* getClient takes a KMS client constructor
   * and optional configuration values.
   * The credentials can be injected here,
   * because browser do not have a standard credential discover process the way Node.js does.
   */
  const clientProvider = getClient(KMS, {
    credentials: {
      accessKeyId,
      secretAccessKey,
      sessionToken
    }
  })

  /* The KMS keyring must be configured with the desired CMKs */
  const keyring = new KmsKeyringBrowser({ clientProvider, generatorKeyId, keyIds })

  /* Create a cache to hold the material.
   * In this case we use the local cache provided by the Encryption SDK.
   * The number is the maximum number of entries that will be cached.
   * Both encrypt and decrypt requests count independently towards this total.
   * Elements will be actively removed from the cache.
   * The default frequency is to check one item every minute.
   * This can be configure by passing a `proactiveFrequency`
   * as the second paramter to however often you want to check in milliseconds.
   */
  const cache = getLocalCryptographicMaterialsCache(100)

  /* The partition name lets multiple caching CMMs share the same local cryptographic cache.
   * If you want these CMMs to all cache the same items,
   * make the partition name the same.
   * If no partition is supplied a random one will be generated.
   * This is so that sharing elements in the cache MUST be an intentional operation.
   */
  const partition = 'local partition name'

  /* maxAge is the time in milliseconds that an entry will be cached.
   * Elements are actively removed from the cache.
   */
  const maxAge = 1000 * 60

  /* The maximum amount of bytes that will be encrypted under a single data key.
   * This value is optional, but you should be configured to a lower value.
   */
  const maxBytesEncrypted = 100

  /* The maximum number of messages that will be encrypted under a single data key.
   * This value is optional, but you should be configured to a lower value.
   */
  const maxMessagesEncrypted = 100

  const cmm = new WebCryptoCachingMaterialsManager({
    backingMaterials: keyring,
    cache,
    partition,
    maxAge,
    maxBytesEncrypted,
    maxMessagesEncrypted
  })

  /* Encryption context is a *very* powerful tool for controlling and managing access.
   * It is ***not*** secret!
   * Encrypted data is opaque.
   * You can use an encryption context to assert things about the encrypted data.
   * Just because you can decrypt something does not mean it is what you expect.
   * For example, if you are are only expecting data from 'us-west-2',
   * the origin can identify a malicious actor.
   * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
   *
   * DATA KEYS FOR MESSAGES WILL ***ONLY*** BE SHARED FOR EXACT MATCHES OF ENCRYPTION CONTEXT.
   * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-caching-details.html#caching-encryption-context
   */
  const encryptionContext = {
    stage: 'demo',
    purpose: 'simple demonstration app',
    origin: 'us-west-2'
  }

  /* Find data to encrypt. */
  const plainText = new Uint8Array([1, 2, 3, 4, 5])

  /* Encrypt the data.
   * Data keys for messages will only be shared if a plaintextlength is passed
   * HOWEVER, FOR THE BROWSER, ALL CRYPTOGRAPHIC OPERATIONS ARE ONE-SHOT.
   * This means that the plaintextLength is _always_ know.
   * So it is not a passable option to avoid mismatches.
   */
  const { ciphertext } = await encrypt(cmm, plainText, { encryptionContext })

  /* Log the plain text
   * only for testing and to show that it works.
   */
  console.log('plainText:', plainText)
  document.write('</br>plainText:' + plainText + '</br>')

  /* Log the base64-encoded ciphertext
   * so that you can try decrypting it with another AWS Encryption SDK implementation.
   */
  const ciphertextBase64 = toBase64(ciphertext)
  console.log(ciphertextBase64)
  document.write(ciphertextBase64)

  /* Decrypt the data.
   * NOTE: THIS REQUEST IS ***NOT*** CACHED BECAUSE OF THE ENCRYPT REQUEST ABOVE!
   * Encrypt and decrypt materials are stored separately.
   */
  const { plaintext, messageHeader } = await decrypt(cmm, ciphertext)

  /* Grab the encryption context so you can verify it. */
  const { encryptionContext: decryptedContext } = messageHeader

  /* Verify the encryption context.
   * If you use an algorithm suite with signing,
   * the Encryption SDK adds a name-value pair to the encryption context that contains the public key.
   * Because the encryption context might contain additional key-value pairs,
   * do not add a test that requires that all key-value pairs match.
   * Instead, verify that the key-value pairs you expect match.
   */
  Object
    .entries(encryptionContext)
    .forEach(([key, value]) => {
      if (decryptedContext[key] !== value) throw new Error('Encryption Context does not match expected values')
    })

  /* Log the clear message
   * only for testing and to show that it works.
   */
  document.write('</br>Decrypted:' + plaintext)
  console.log(plaintext)

  /* Return the values to make testing easy. */
  return { plainText, plaintext }
}
