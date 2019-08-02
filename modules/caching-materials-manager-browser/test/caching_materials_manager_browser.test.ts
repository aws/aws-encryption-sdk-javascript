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
import { WebCryptoCachingMaterialsManager } from '../src/index'
import { } from '@aws-crypto/cache-material'
import {
  KeyringWebCrypto,
  WebCryptoDefaultCryptographicMaterialsManager,
  WebCryptoEncryptionMaterial, // eslint-disable-line no-unused-vars
  WebCryptoDecryptionMaterial // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-browser'

describe('WebCryptoCachingMaterialsManager', () => {
  it('constructor will decorate', () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('never')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
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
      maxMessagesEncrypted
    })

    expect(test._backingMaterialsManager).to.be.instanceOf(WebCryptoDefaultCryptographicMaterialsManager)
    expect(test._cache).to.equal(cache)
    expect(test._partition).to.equal(partition)
    expect(test._maxAge).to.equal(maxAge)
    expect(test._maxBytesEncrypted).to.equal(maxBytesEncrypted)
    expect(test._maxMessagesEncrypted).to.equal(maxMessagesEncrypted)
  })

  it('Precondition: A partition value must exist for WebCryptoCachingMaterialsManager.', () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('never')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('never')
      }
    }

    const keyring = new TestKeyring()
    const cache = 'cache' as any
    const maxAge = 10
    const test = new WebCryptoCachingMaterialsManager({
      backingMaterials: keyring,
      cache,
      maxAge
    })
    /* 64 Bytes of data encoded as base64 will be 88 characters long.
     */
    expect(test._partition).to.be.a('string').and.to.have.lengthOf(88)
  })
})
