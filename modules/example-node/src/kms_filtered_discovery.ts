// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringNode,
  getKmsClient,
  buildClient,
  CommitmentPolicy,
} from '@aws-crypto/client-node'

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

export async function kmsFilteredDiscoveryTest(
  ciphertext: string | Buffer,
  accountID: string,
  partition: string
) {
  const discovery = true
  const clientProvider = getKmsClient
  /* This filter will only attempt to decrypt CMKs
   * in `accountID` and `partition`.
   */
  const discoveryFilter = {
    accountIDs: [accountID],
    partition,
  }
  const keyring = new KmsKeyringNode({
    clientProvider,
    discovery,
    discoveryFilter,
  })

  const cleartext = await decrypt(keyring, ciphertext)

  return { ciphertext, cleartext }
}
