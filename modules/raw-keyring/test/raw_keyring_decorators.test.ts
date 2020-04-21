// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { _onEncrypt, _onDecrypt } from '../src/raw_keyring_decorators'
import {
  AlgorithmSuiteIdentifier,
  NodeEncryptionMaterial,
  NodeAlgorithmSuite,
  KeyringTraceFlag,
  NodeDecryptionMaterial,
  EncryptedDataKey,
  unwrapDataKey,
} from '@aws-crypto/material-management'

describe('_onEncrypt', () => {
  it('will create UnencryptedDataKey and call _wrapKey', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new NodeEncryptionMaterial(suite, {})
    let wrapCalled = 0
    const notRandomBytes = async (bytes: number) =>
      new Uint8Array(Array(bytes).fill(1))
    const _wrapKey = (material: any) => {
      wrapCalled += 1
      return material
    }
    const keyName = 'keyName'
    const keyNamespace = 'keyNamespace'

    const testKeyring = {
      keyName,
      keyNamespace,
      _onEncrypt: _onEncrypt(notRandomBytes),
      _wrapKey,
    } as any

    const test = await testKeyring._onEncrypt(material)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(
      new Uint8Array(Array(suite.keyLengthBytes).fill(1))
    )
    expect(test.keyringTrace).to.have.lengthOf(1)
    expect(test.keyringTrace[0].keyName).to.equal(keyName)
    expect(test.keyringTrace[0].keyNamespace).to.equal(keyNamespace)
    expect(test.keyringTrace[0].flags).to.equal(
      KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    )
    expect(wrapCalled).to.equal(1)
  })

  it('will not create a UnencryptedDataKey if one exists, but will call _wrapKey', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const udk = new Uint8Array(Array(suite.keyLengthBytes).fill(2))
    const keyName = 'keyName'
    const keyNamespace = 'keyNamespace'
    const material = new NodeEncryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(udk), {
      keyName,
      keyNamespace,
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })
    let wrapCalled = 0
    const notRandomBytes = async () => {
      throw new Error('never')
    }
    const _wrapKey = (material: any) => {
      wrapCalled += 1
      return material
    }

    const testKeyring = {
      keyName,
      keyNamespace,
      _onEncrypt: _onEncrypt(notRandomBytes),
      _wrapKey,
    } as any

    const test = await testKeyring._onEncrypt(material)
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk)
    expect(wrapCalled).to.equal(1)
  })
})

describe('_onDecrypt', () => {
  it('basic usage', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const udk = new Uint8Array(Array(suite.keyLengthBytes).fill(2))
    const material = new NodeDecryptionMaterial(suite, {})
    const keyName = 'keyName'
    const keyNamespace = 'keyNamespace'

    const edk = new EncryptedDataKey({
      providerId: keyName,
      providerInfo: keyNamespace,
      encryptedDataKey: new Uint8Array(5),
    })
    let unwrapCalled = 0
    let filterCalled = 0

    const _filter = () => {
      filterCalled += 1
      return true
    }
    const _unwrapKey = (material: NodeDecryptionMaterial) => {
      unwrapCalled += 1
      return material.setUnencryptedDataKey(new Uint8Array(udk), {
        keyName,
        keyNamespace,
        flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
      })
    }

    const testKeyring = {
      keyName,
      keyNamespace,
      _onDecrypt: _onDecrypt(),
      _unwrapKey,
      _filter,
    } as any

    const test = await testKeyring._onDecrypt(material, [edk])
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk)
    expect(test.keyringTrace).to.have.lengthOf(1)
    expect(test.keyringTrace[0].keyName).to.equal(keyName)
    expect(test.keyringTrace[0].keyNamespace).to.equal(keyNamespace)
    expect(test.keyringTrace[0].flags).to.equal(
      KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    )
    expect(unwrapCalled).to.equal(1)
    expect(filterCalled).to.equal(1)
  })

  it('Check for early return (Postcondition): If the material is already valid, attempting to decrypt is a bad idea.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const udk = new Uint8Array(Array(suite.keyLengthBytes).fill(2))
    const keyName = 'keyName'
    const keyNamespace = 'keyNamespace'
    const material = new NodeDecryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(udk), {
      keyName,
      keyNamespace,
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    })

    const edk = new EncryptedDataKey({
      providerId: keyName,
      providerInfo: keyNamespace,
      encryptedDataKey: new Uint8Array(5),
    })
    let unwrapCalled = 0
    let filterCalled = 0

    const _filter = () => {
      filterCalled += 1
      return true
    }
    const _unwrapKey = (material: NodeDecryptionMaterial) => {
      unwrapCalled += 1
      return material
    }

    const testKeyring = {
      keyName,
      keyNamespace,
      _onDecrypt: _onDecrypt(),
      _unwrapKey,
      _filter,
    } as any

    const test = await testKeyring._onDecrypt(material, [edk])
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(udk)
    expect(unwrapCalled).to.equal(0)
    expect(filterCalled).to.equal(0)
  })

  it('Check for early return (Postcondition): If there are not EncryptedDataKeys for this keyring, do nothing.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const keyName = 'keyName'
    const keyNamespace = 'keyNamespace'
    const material = new NodeDecryptionMaterial(suite, {})

    const edk = new EncryptedDataKey({
      providerId: keyName,
      providerInfo: keyNamespace,
      encryptedDataKey: new Uint8Array(5),
    })
    let unwrapCalled = 0
    let filterCalled = 0

    const _filter = () => {
      filterCalled += 1
      return false
    }
    const _unwrapKey = (material: NodeDecryptionMaterial) => {
      unwrapCalled += 1
      return material
    }

    const testKeyring = {
      keyName,
      keyNamespace,
      _onDecrypt: _onDecrypt(),
      _unwrapKey,
      _filter,
    } as any

    const test = await testKeyring._onDecrypt(material, [edk])
    expect(test.hasValidKey()).to.equal(false)
    expect(unwrapCalled).to.equal(0)
    expect(filterCalled).to.equal(1)
  })

  it('errors in _unwrapKey should not cause _onDecrypt to throw.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const keyName = 'keyName'
    const keyNamespace = 'keyNamespace'
    const material = new NodeDecryptionMaterial(suite, {})

    const edk = new EncryptedDataKey({
      providerId: keyName,
      providerInfo: keyNamespace,
      encryptedDataKey: new Uint8Array(5),
    })
    let unwrapCalled = 0
    let filterCalled = 0

    const _filter = () => {
      filterCalled += 1
      return true
    }
    const _unwrapKey = () => {
      unwrapCalled += 1
      throw new Error('something')
    }

    const testKeyring = {
      keyName,
      keyNamespace,
      _onDecrypt: _onDecrypt(),
      _unwrapKey,
      _filter,
    } as any

    const test = await testKeyring._onDecrypt(material, [edk])
    expect(test.hasValidKey()).to.equal(false)
    expect(unwrapCalled).to.equal(1)
    expect(filterCalled).to.equal(1)
  })
})
