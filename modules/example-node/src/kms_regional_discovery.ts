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

import { KmsKeyringNode, limitRegions, excludeRegions, getKmsClient, decrypt } from '@aws-crypto/client-node'

export async function kmsRegionalDiscoveryLimitTest (ciphertext: string|Buffer) {
  const discovery = true
  // This provider will *only* decrypt for keys in the us-east-1 region.
  const clientProvider = limitRegions(['us-east-1'], getKmsClient)
  const keyring = new KmsKeyringNode({ clientProvider, discovery })

  const cleartext = await decrypt(keyring, ciphertext)

  return { ciphertext, cleartext }
}

export async function kmsRegionalDiscoveryExcludeTest (ciphertext: string|Buffer) {
  const discovery = true
  // This provider will decrypt for keys in any region except us-east-1.
  const clientProvider = excludeRegions(['us-east-1'], getKmsClient)
  const keyring = new KmsKeyringNode({ clientProvider, discovery })

  const cleartext = await decrypt(keyring, ciphertext)

  return { ciphertext, cleartext }
}
