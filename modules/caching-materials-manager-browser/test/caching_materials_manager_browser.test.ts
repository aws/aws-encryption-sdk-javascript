// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
// import 'mocha'
import { WebCryptoCachingMaterialsManager } from '../src/index'
import {} from '@aws-crypto/cache-material'
import {
  KeyringWebCrypto,
  WebCryptoDefaultCryptographicMaterialsManager,
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
} from '@aws-crypto/material-management-browser'

describe('WebCryptoCachingMaterialsManager', () => {
  it('constructor will decorate', () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('never')
      }
      async _onDecrypt(): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('never')
      }
    }

    const keyring = new TestKeyring()
    const cache = 'cache' as any
    const partition = 'partition'
    const maxAge = 10
    const maxBytesEncrypted = 11
    const maxMessagesEncrypted = 12
    const test = new WebCryptoCachingMaterialsManager({
      backingMaterials: keyring,
      cache,
      partition,
      maxAge,
      maxBytesEncrypted,
      maxMessagesEncrypted,
    })

    expect(test._backingMaterialsManager).to.be.instanceOf(
      WebCryptoDefaultCryptographicMaterialsManager
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

  it('Precondition: A partition value must exist for WebCryptoCachingMaterialsManager.', () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('never')
      }
      async _onDecrypt(): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('never')
      }
    }

    const keyring = new TestKeyring()
    const cache = 'cache' as any
    const maxAge = 10
    const test = new WebCryptoCachingMaterialsManager({
      backingMaterials: keyring,
      cache,
      maxAge,
    })
    /* 64 Bytes of data encoded as base64 will be 88 characters long.
     */
    expect(test._partition).to.be.a('string').and.to.have.lengthOf(88)
  })
})
