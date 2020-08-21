// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringNode,
  getKmsClient,
  buildClient,
  CommitmentPolicy,
} from '@aws-crypto/client-node'
const { decrypt } = buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
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
