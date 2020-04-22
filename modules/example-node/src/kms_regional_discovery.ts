// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  KmsKeyringNode,
  limitRegions,
  excludeRegions,
  getKmsClient,
  decrypt,
} from '@aws-crypto/client-node'

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
