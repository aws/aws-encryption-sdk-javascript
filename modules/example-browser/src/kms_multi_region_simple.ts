// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  buildAwsKmsMrkAwareStrictMultiKeyringBrowser,
  buildClient,
  CommitmentPolicy,
  KMS,
} from '@aws-crypto/client-browser'
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

/* This is injected by webpack.
 * The webpack.DefinePlugin will replace the values when bundling.
 * The credential values are pulled from @aws-sdk/credential-provider-node
 * Use any method you like to get credentials into the browser.
 * See kms.webpack.config
 */
declare const credentials: {
  accessKeyId: string
  secretAccessKey: string
  sessionToken: string
}
/* The credentials can be injected here,
 * because browser do not have a standard credential discover process the way Node.js does.
 */
const clientProvider = (region: string) => new KMS({ region, credentials })

export async function kmsMultiRegionSimpleTest() {
  /* A KMS CMK is required to generate the data key.
   * You need kms:GenerateDataKey permission on the CMK in generatorKeyId.
   * In this example we are using two related multi-Region keys.
   * We will encrypt with the us-east-1 multi-Region key first.
   */
  const multiRegionUsEastKey =
    'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'

  /* The AWS KMS MRK Aware keyring must be configured with the related CMK. */
  const encryptKeyring = buildAwsKmsMrkAwareStrictMultiKeyringBrowser({
    generatorKeyId: multiRegionUsEastKey,
    clientProvider,
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
  const cleartext = new Uint8Array([1, 2, 3, 4, 5])

  /* Encrypt the data. */
  const { result } = await encrypt(encryptKeyring, cleartext, {
    encryptionContext: context,
  })

  /* A KMS CMK is required to decrypt the data key.
   * Access to kms:Decrypt is required for this example.
   * Having encrypted with a multi-Region key in us-east-1
   * we will decrypt this message with a related multi-Region key.
   */
  const multiRegionUsWestKey =
    'arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'

  /* The AWS KMS MRK Aware keyring must be configured with the related CMK. */
  const decryptKeyring = buildAwsKmsMrkAwareStrictMultiKeyringBrowser({
    generatorKeyId: multiRegionUsWestKey,
    clientProvider,
  })

  /* Decrypt the data. */
  const { plaintext, messageHeader } = await decrypt(decryptKeyring, result)

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
  return { plaintext, result, cleartext, messageHeader }
}
