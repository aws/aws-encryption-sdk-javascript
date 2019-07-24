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

import {
  CachingMaterialsManager, // eslint-disable-line no-unused-vars
  decorateProperties,
  getEncryptionMaterials,
  decryptMaterials,
  cacheEntryHasExceededLimits,
  buildCryptographicMaterialsCacheKeyHelpers,
  CachingMaterialsManagerInput, // eslint-disable-line no-unused-vars
  CryptographicMaterialsCache // eslint-disable-line no-unused-vars
} from '@aws-crypto/cache-material'
import {
  NodeMaterialsManager, // eslint-disable-line no-unused-vars
  NodeDefaultCryptographicMaterialsManager,
  NodeAlgorithmSuite, // eslint-disable-line no-unused-vars
  KeyringNode,
  NodeGetEncryptionMaterials, // eslint-disable-line no-unused-vars
  NodeGetDecryptMaterials // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import { sha512 } from './sha512'
import { randomBytes } from 'crypto'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString('utf8')

const cacheKeyHelpers = buildCryptographicMaterialsCacheKeyHelpers(fromUtf8, toUtf8, sha512)

export class NodeCachingMaterialsManager implements CachingMaterialsManager<NodeAlgorithmSuite> {
  readonly _cache!: CryptographicMaterialsCache<NodeAlgorithmSuite>
  readonly _backingMaterialsManager!: NodeMaterialsManager
  readonly _partition!: string
  readonly _maxBytesEncrypted!: number
  readonly _maxMessagesEncrypted!: number
  readonly _maxAge!: number

  constructor (input: CachingMaterialsManagerInput<NodeAlgorithmSuite>) {
    const backingMaterialsManager = input.backingMaterials instanceof KeyringNode
      ? new NodeDefaultCryptographicMaterialsManager(input.backingMaterials)
      : <NodeDefaultCryptographicMaterialsManager>input.backingMaterials

    /* Precondition: A partition value must exist for NodeCachingMaterialsManager.
     * The maximum hash function at this time is 512.
     * So I create 64 bytes of random data.
     */
    const { partition = randomBytes(64).toString('utf8') } = input

    decorateProperties(this, {
      ...input,
      backingMaterialsManager,
      partition
    })
  }

  getEncryptionMaterials: NodeGetEncryptionMaterials = getEncryptionMaterials<NodeAlgorithmSuite>(cacheKeyHelpers)
  decryptMaterials: NodeGetDecryptMaterials = decryptMaterials<NodeAlgorithmSuite>(cacheKeyHelpers)
  _cacheEntryHasExceededLimits = cacheEntryHasExceededLimits<NodeAlgorithmSuite>()
}
