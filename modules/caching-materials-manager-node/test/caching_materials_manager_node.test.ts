// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { NodeCachingMaterialsManager } from '../src/index'
import {} from '@aws-crypto/cache-material'
import {
  KeyringNode,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  NodeDefaultCryptographicMaterialsManager,
} from '@aws-crypto/material-management-node'

describe('NodeCachingMaterialsManager', () => {
  it('constructor will decorate', () => {
    class TestKeyring extends KeyringNode {
      async _onEncrypt(): Promise<NodeEncryptionMaterial> {
        throw new Error('never')
      }
      async _onDecrypt(): Promise<NodeDecryptionMaterial> {
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
      maxMessagesEncrypted,
    })

    expect(test._backingMaterialsManager).to.be.instanceOf(
      NodeDefaultCryptographicMaterialsManager
    )
    expect(test).to.haveOwnPropertyDescriptor('_cache', {
      value: cache,
      writable: false,
      enumerable: true,
      configurable: false,
    })
    expect(test).to.haveOwnPropertyDescriptor('_partition', {
      value: partition,
      writable: false,
      enumerable: true,
      configurable: false,
    })
    expect(test).to.haveOwnPropertyDescriptor('_maxAge', {
      value: maxAge,
      writable: false,
      enumerable: true,
      configurable: false,
    })
    expect(test).to.haveOwnPropertyDescriptor('_maxBytesEncrypted', {
      value: maxBytesEncrypted,
      writable: false,
      enumerable: true,
      configurable: false,
    })
    expect(test).to.haveOwnPropertyDescriptor('_maxMessagesEncrypted', {
      value: maxMessagesEncrypted,
      writable: false,
      enumerable: true,
      configurable: false,
    })
  })

  it('Precondition: A partition value must exist for NodeCachingMaterialsManager.', () => {
    class TestKeyring extends KeyringNode {
      async _onEncrypt(): Promise<NodeEncryptionMaterial> {
        throw new Error('never')
      }
      async _onDecrypt(): Promise<NodeDecryptionMaterial> {
        throw new Error('never')
      }
    }

    const keyring = new TestKeyring()
    const cache = 'cache' as any
    const maxAge = 10
    const test = new NodeCachingMaterialsManager({
      backingMaterials: keyring,
      cache,
      maxAge,
    })
    /* Binary data is being transformed to base64.
     * 64 bits of base64 encoded data is 88 characters.
     */
    expect(test._partition).to.be.a('string').and.to.have.lengthOf(88)
  })
})
