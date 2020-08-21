// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringNode,
  limitRegions,
  excludeRegions,
  getKmsClient,
  buildClient,
  CommitmentPolicy,
} from '@aws-crypto/client-node'
const { decrypt } = buildClient(CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
export async function kmsRegionalDiscoveryLimitTest(
  ciphertext: string | Buffer
) {
  const discovery = true
  // This provider will *only* decrypt for keys in the us-east-1 region.
  const clientProvider = limitRegions(['us-east-1'], getKmsClient)
  const keyring = new KmsKeyringNode({ clientProvider, discovery })

  const cleartext = await decrypt(keyring, ciphertext)

  return { ciphertext, cleartext }
}

export async function kmsRegionalDiscoveryExcludeTest(
  ciphertext: string | Buffer
) {
  const discovery = true
  // This provider will decrypt for keys in any region except us-east-1.
  const clientProvider = excludeRegions(['us-east-1'], getKmsClient)
  const keyring = new KmsKeyringNode({ clientProvider, discovery })

  const cleartext = await decrypt(keyring, ciphertext)

  return { ciphertext, cleartext }
}
