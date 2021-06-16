// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  AwsKmsMrkAwareSymmetricDiscoveryKeyringBrowser,
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
const { decrypt } = buildClient(
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

export async function kmsMultiRegionDiscoveryTest(ciphertext: Uint8Array) {
  /* Create an AWS KMS Client.
   * This client will be used for all multi-Region keys.
   */
  const client = new KMS({ region: 'us-west-2', credentials })
  /* Create discovery filter for decrypting.
   * This filter restricts what AWS KMS CMKs
   * the AWS KMS multi region optimized master key provider can use
   * to those in a particular AWS partition and account.
   * You can create a similar filter with one partition and multiple AWS accounts.
   * This example only configures the filter with one account,
   * but more may be specified as long as they exist within the same partition.
   * This filter is not required for Discovery mode, but is a best practice.
   */

  const discoveryFilter = { partition: 'aws', accountIDs: ['658956600833'] }

  /* Instantiate an AwsKmsMrkAwareSymmetricDiscoveryKeyringNode with the client and filter. */
  const keyring = new AwsKmsMrkAwareSymmetricDiscoveryKeyringBrowser({
    client,
    discoveryFilter,
  })

  /* Decrypt the data. */
  const { messageHeader, plaintext } = await decrypt(keyring, ciphertext)

  /* Verify the encryption context.
   * If you use an algorithm suite with signing,
   * the Encryption SDK adds a name-value pair to the encryption context that contains the public key.
   * Because the encryption context might contain additional key-value pairs,
   * do not add a test that requires that all key-value pairs match.
   * Instead, verify that the key-value pairs you expect match.
   */
  const context = {
    stage: 'demo',
    purpose: 'simple demonstration app',
    origin: 'us-west-2',
  }
  Object.entries(context).forEach(([key, value]) => {
    if (messageHeader.encryptionContext[key] !== value)
      throw new Error('Encryption Context does not match expected values')
  })

  /* Return the values so the code can be tested. */
  return { messageHeader, plaintext }
}
