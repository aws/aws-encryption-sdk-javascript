// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  buildClient,
  CommitmentPolicy,
  BranchKeyStoreNode,
  KmsHierarchicalKeyRingNode,
} from '@aws-crypto/client-node'
/* This builds the client with the FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy.
 * This configuration should only be used
 * as part of a migration
 * from version 1.x to 2.x,
 * or for advanced users
 * with specialized requirements.
 * We recommend that AWS Encryption SDK users
 * enable commitment whenever possible.
 */
const { encrypt, decrypt } = buildClient(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
)

export async function hKeyringDisableCommitmentTest(
  keyStoreTableName = 'KeyStoreDdbTable',
  logicalKeyStoreName = keyStoreTableName,
  kmsKeyId = 'arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'
) {
  // Configure your KeyStore resource.
  //    This SHOULD be the same configuration that you used
  //    to initially create and populate your KeyStore.
  const keyStore = new BranchKeyStoreNode({
    storage: {ddbTableName: keyStoreTableName},
    logicalKeyStoreName: logicalKeyStoreName,
    kmsConfiguration: { identifier: kmsKeyId },
  })

  // Here, you would call CreateKey to create an active branch keys
  // However, the JS keystore does not currently support this operation, so we
  // hard code the ID of an existing active branch key
  const branchKeyId = '38853b56-19c6-4345-9cb5-afc2a25dcdd1'

  // Create the Hierarchical Keyring.
  const keyring = new KmsHierarchicalKeyRingNode({
    branchKeyId,
    keyStore,
    cacheLimitTtl: 600, // 10 min
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
  return { plaintext, result, cleartext, messageHeader }
}
