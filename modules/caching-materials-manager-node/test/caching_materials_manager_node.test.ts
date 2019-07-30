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

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import { NodeCachingMaterialsManager } from '../src/index'
import { } from '@aws-crypto/cache-material'
import {
  KeyringNode,
  NodeDefaultCryptographicMaterialsManager,
  NodeEncryptionMaterial, // eslint-disable-line no-unused-vars
  NodeDecryptionMaterial // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'

describe('NodeCachingMaterialsManager', () => {
  it('constructor will decorate', () => {
    class TestKeyring extends KeyringNode {
      async _onEncrypt (): Promise<NodeEncryptionMaterial> {
        throw new Error('never')
      }
      async _onDecrypt (): Promise<NodeDecryptionMaterial> {
        throw new Error('never')
      }
    }

    const keyring = new TestKeyring()
    const cache = 'cache' as any
    const partition = 'partition'
    const maxAge = 10
    const maxBytesEncrypted = 11
    const maxMessagesEncrypted = 12
    const test = new NodeCachingMaterialsManager({
      backingMaterials: keyring,
      cache,
      partition,
      maxAge,
      maxBytesEncrypted,
      maxMessagesEncrypted
    })

    expect(test._backingMaterialsManager).to.be.instanceOf(NodeDefaultCryptographicMaterialsManager)
    expect(test._cache).to.equal(cache)
    expect(test._partition).to.equal(partition)
    expect(test._maxAge).to.equal(maxAge)
    expect(test._maxBytesEncrypted).to.equal(maxBytesEncrypted)
    expect(test._maxMessagesEncrypted).to.equal(maxMessagesEncrypted)
  })

  it('Precondition: A partition value must exist for NodeCachingMaterialsManager.', () => {
    class TestKeyring extends KeyringNode {
      async _onEncrypt (): Promise<NodeEncryptionMaterial> {
        throw new Error('never')
      }
      async _onDecrypt (): Promise<NodeDecryptionMaterial> {
        throw new Error('never')
      }
    }

    const keyring = new TestKeyring()
    const cache = 'cache' as any
    const maxAge = 10
    const test = new NodeCachingMaterialsManager({
      backingMaterials: keyring,
      cache,
      maxAge
    })
    /* Binary data is being transformed to base64.
     * 64 bits of base64 encoded data is 88 characters.
     */
    expect(test._partition).to.be.a('string').and.to.have.lengthOf(88)
  })
})
