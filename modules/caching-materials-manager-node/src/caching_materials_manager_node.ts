// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  CachingMaterialsManager,
  decorateProperties,
  getEncryptionMaterials,
  decryptMaterials,
  cacheEntryHasExceededLimits,
  buildCryptographicMaterialsCacheKeyHelpers,
  CryptographicMaterialsCache,
  CachingMaterialsManagerInput,
} from '@aws-crypto/cache-material'
import {
  NodeMaterialsManager,
  NodeDefaultCryptographicMaterialsManager,
  NodeAlgorithmSuite,
  KeyringNode,
  NodeGetEncryptionMaterials,
  NodeGetDecryptMaterials,
} from '@aws-crypto/material-management-node'
import { sha512 } from './sha512'
import { randomBytes } from 'crypto'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString('utf8')

const cacheKeyHelpers = buildCryptographicMaterialsCacheKeyHelpers(
  fromUtf8,
  toUtf8,
  sha512
)

export class NodeCachingMaterialsManager
  implements CachingMaterialsManager<NodeAlgorithmSuite>
{
  declare readonly _cache: CryptographicMaterialsCache<NodeAlgorithmSuite>
  declare readonly _backingMaterialsManager: NodeMaterialsManager
  declare readonly _partition: string
  declare readonly _maxBytesEncrypted: number
  declare readonly _maxMessagesEncrypted: number
  declare readonly _maxAge: number

  constructor(input: CachingMaterialsManagerInput<NodeAlgorithmSuite>) {
    const backingMaterialsManager =
      input.backingMaterials instanceof KeyringNode
        ? new NodeDefaultCryptographicMaterialsManager(input.backingMaterials)
        : (input.backingMaterials as NodeDefaultCryptographicMaterialsManager)

    /* Precondition: A partition value must exist for NodeCachingMaterialsManager.
     * The maximum hash function at this time is 512.
     * So I create 64 bytes of random data.
     */
    const { partition = randomBytes(64).toString('base64') } = input

    decorateProperties(this, {
      ...input,
      backingMaterialsManager,
      partition,
    })
  }

  getEncryptionMaterials: NodeGetEncryptionMaterials =
    getEncryptionMaterials<NodeAlgorithmSuite>(cacheKeyHelpers)
  decryptMaterials: NodeGetDecryptMaterials =
    decryptMaterials<NodeAlgorithmSuite>(cacheKeyHelpers)
  _cacheEntryHasExceededLimits =
    cacheEntryHasExceededLimits<NodeAlgorithmSuite>()
}
