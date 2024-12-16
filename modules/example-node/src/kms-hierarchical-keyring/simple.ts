// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  BranchKeyStoreNode,
  buildClient,
  CommitmentPolicy,
  KmsHierarchicalKeyRingNode,
} from '@aws-crypto/client-node'

/**
 * This example sets up the Hierarchical Keyring, which establishes a key hierarchy where "branch"
 * keys are persisted in DynamoDb. These branch keys are used to protect your data keys, and these
 * branch keys are themselves protected by a KMS Key.
 *
 * Establishing a key hierarchy like this has two benefits:
 *
 * First, by caching the branch key material, and only calling KMS to re-establish authentication
 * regularly according to your configured TTL, you limit how often you need to call KMS to protect
 * your data. This is a performance security tradeoff, where your authentication, audit, and logging
 * from KMS is no longer one-to-one with every encrypt or decrypt call. Additionally, KMS Cloudtrail
 * cannot be used to distinguish Encrypt and Decrypt calls, and you cannot restrict who has
 * Encryption rights from who has Decryption rights since they both ONLY need KMS:Decrypt. However,
 * the benefit is that you no longer have to make a network call to KMS for every encrypt or
 * decrypt.
 *
 * Second, this key hierarchy facilitates cryptographic isolation of a tenant's data in a
 * multi-tenant data store. Each tenant can have a unique Branch Key, that is only used to protect
 * the tenant's data. You can either statically configure a single branch key to ensure you are
 * restricting access to a single tenant, or you can implement an interface that selects the Branch
 * Key based on the Encryption Context.
 *
 * This example demonstrates statically configuring a Hierarchical Keyring with
 * a single branch key to showcase how access can be restricted to a single tenant.
 *
 * This example requires access to the DDB Table where you are storing the Branch Keys. This
 * table must be configured with the following primary key configuration: - Partition key is named
 * "partition_key" with type (S) - Sort key is named "sort_key" with type (S)
 *
 * This example also requires using a KMS Key. You need the following access on this key: -
 * GenerateDataKeyWithoutPlaintext - Decrypt
 */

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

export async function hKeyringSimpleTest(
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
