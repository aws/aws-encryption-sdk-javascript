// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  BranchKeyStoreNode,
  buildClient,
  CommitmentPolicy,
  KmsHierarchicalKeyRingNode,
  BranchKeyIdSupplier,
  EncryptionContext,
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
 * This example demonstrates configuring a Hierarchical Keyring with a Branch Key ID Supplier to
 * encrypt and decrypt data for two separate tenants.
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

// Implement an example branch key id supplier
// Use the encryption contexts to define friendly names for each branch key
class ExampleBranchKeyIdSupplier implements BranchKeyIdSupplier {
  private _branchKeyIdForTenantA: string
  private _branchKeyIdForTenantB: string

  constructor(tenant1Id: string, tenant2Id: string) {
    this._branchKeyIdForTenantA = tenant1Id
    this._branchKeyIdForTenantB = tenant2Id
  }

  getBranchKeyId(encryptionContext: EncryptionContext): string {
    if ('tenant' in encryptionContext === false) {
      throw new Error(
        'EncryptionContext invalid, does not contain expected tenant key value pair.'
      )
    }

    const tenantKeyId = encryptionContext['tenant']
    let branchKeyId: string

    if (tenantKeyId === 'TenantA') {
      branchKeyId = this._branchKeyIdForTenantA
    } else if (tenantKeyId === 'TenantB') {
      branchKeyId = this._branchKeyIdForTenantB
    } else {
      throw new Error('Item does not contain valid tenant ID')
    }

    return branchKeyId
  }
}

export async function hKeyringMultiTenancy(
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

  // Here, you would call CreateKey to create two new active branch keys.
  // However, the JS keystore does not currently support this operation, so we
  // hard code the IDs of two existing active branch keys
  const branchKeyIdA = '38853b56-19c6-4345-9cb5-afc2a25dcdd1'
  const branchKeyIdB = '2c583585-5770-467d-8f59-b346d0ed1994'

  // Create a branch key supplier that maps the branch key id to a more readable format
  const branchKeyIdSupplier = new ExampleBranchKeyIdSupplier(
    branchKeyIdA,
    branchKeyIdB
  )

  // Create the Hierarchical Keyring.
  const keyring = new KmsHierarchicalKeyRingNode({
    branchKeyIdSupplier,
    keyStore,
    cacheLimitTtl: 600, // 10 min
  })

  // The Branch Key Id supplier uses the encryption context to determine which branch key id will
  // be used to encrypt data.
  // Create encryption context for TenantA
  const encryptionContextAIn = {
    tenant: 'TenantA',
    encryption: 'context',
    'is not': 'secret',
    'but adds': 'useful metadata',
    'that can help you': 'be confident that',
    'the data you are handling': 'is what you think it is',
  }

  // Create encryption context for TenantB
  const encryptionContextBIn = {
    tenant: 'TenantB',
    encryption: 'context',
    'is not': 'secret',
    'but adds': 'useful metadata',
    'that can help you': 'be confident that',
    'the data you are handling': 'is what you think it is',
  }

  /* Find data to encrypt.  A simple string. */
  const cleartext = 'asdf'

  // Encrypt the data for encryptionContextA & encryptionContextB
  const { result: encryptResultA } = await encrypt(keyring, cleartext, {
    encryptionContext: encryptionContextAIn,
  })
  const { result: encryptResultB } = await encrypt(keyring, cleartext, {
    encryptionContext: encryptionContextBIn,
  })

  // To attest that TenantKeyB cannot decrypt a message written by TenantKeyA
  // let's construct more restrictive hierarchical keyrings.
  const keyringA = new KmsHierarchicalKeyRingNode({
    branchKeyId: branchKeyIdA,
    keyStore,
    cacheLimitTtl: 600,
  })

  const keyringB = new KmsHierarchicalKeyRingNode({
    branchKeyId: branchKeyIdB,
    keyStore,
    cacheLimitTtl: 600,
  })

  let decryptAFailed = false
  // Try to use keyring for Tenant B to decrypt a message encrypted with Tenant A's key
  // Expected to fail.
  try {
    await decrypt(keyringB, encryptResultA)
  } catch (e) {
    decryptAFailed = true
  }

  let decryptBFailed = false
  // Try to use keyring for Tenant A to decrypt a message encrypted with Tenant B's key
  // Expected to fail.
  try {
    await decrypt(keyringA, encryptResultB)
  } catch (e) {
    decryptBFailed = true
  }

  // we will assert that both decrypts failed
  const decryptsFailed = decryptAFailed && decryptBFailed

  // Decrypt your encrypted data using the same keyring you used on encrypt.

  const { plaintext: plaintextA, messageHeader: messageHeaderA } =
    await decrypt(keyring, encryptResultA)
  /* Grab the encryption context so you can verify it. */
  const { encryptionContext: encryptionContextAOut } = messageHeaderA
  Object.entries(encryptionContextAIn).forEach(([key, value]) => {
    if (encryptionContextAOut[key] !== value)
      throw new Error('Encryption Context does not match expected values')
  })

  const { plaintext: plaintextB, messageHeader: messageHeaderB } =
    await decrypt(keyring, encryptResultB)
  /* Grab the encryption context so you can verify it. */
  const { encryptionContext: encryptionContextBOut } = messageHeaderB
  Object.entries(encryptionContextBIn).forEach(([key, value]) => {
    if (encryptionContextBOut[key] !== value)
      throw new Error('Encryption Context does not match expected values')
  })

  // we will assert that both decrypted plaintexts are the same as the original
  // cleartext

  /* Return the values so the code can be tested. */
  return { decryptsFailed, cleartext, plaintextA, plaintextB }
}
