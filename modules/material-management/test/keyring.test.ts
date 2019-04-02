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

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import 'mocha'
import { NodeEncryptionMaterial, NodeDecryptionMaterial } from '../src/cryptographic_material' // eslint-disable-line no-unused-vars
import { AlgorithmSuiteIdentifier } from '../src/algorithm_suites'
import { NodeAlgorithmSuite } from '../src/node_algorithms'
import { EncryptedDataKey } from '../src/encrypted_data_key'
import { Keyring } from '../src/keyring'
import { EncryptionContext } from '../src/types' // eslint-disable-line no-unused-vars
import { KeyringTraceFlag } from '../src'
chai.use(chaiAsPromised)
const { expect } = chai
const never = () => { throw new Error('never') }

describe('Keyring', () => {
  it('can be extended', () => {
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onEncrypt (material: NodeEncryptionMaterial) {
        return material
      }
      async _onDecrypt (material: NodeDecryptionMaterial) {
        return material
      }
    }
    const test = new TestKeyring()
    expect(test).to.be.instanceOf(Keyring)
  })

  it('onEncrypt calls _onEncrypt', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const { keyLengthBytes } = suite
    const m = new NodeEncryptionMaterial(suite)
    const unencryptedDataKey = new Uint8Array(keyLengthBytes).fill(1)
    let assertCount = 0
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onEncrypt (material: NodeEncryptionMaterial) {
        expect(material.suite === suite).to.equal(true)
        expect(material.hasUnencryptedDataKey).to.equal(false)
        const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
        assertCount += 1
        return material.setUnencryptedDataKey(unencryptedDataKey, trace)
      }
      async _onDecrypt (material: NodeDecryptionMaterial) {
        never()
        return material
      }
    }

    const material = await (new TestKeyring()).onEncrypt(m)
    expect(material === m).to.equal(true)
    expect(assertCount).to.equal(1)
  })

  it('onDecrypt calls _onDecrypt', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const edk = new EncryptedDataKey({ providerId: 'p', providerInfo: 'i', encryptedDataKey: new Uint8Array(3) })
    const material = new NodeDecryptionMaterial(suite)
    const encryptionContext = { some: 'context' }
    let assertCount = 0
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onDecrypt (_material: NodeDecryptionMaterial, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext) {
        expect(_material === material).to.equal(true)
        expect(encryptedDataKeys[0] === edk).to.equal(true)
        expect(context === encryptionContext).to.equal(true)
        assertCount += 1
        return _material
      }
      async _onEncrypt (material: NodeEncryptionMaterial) {
        never()
        return material
      }
    }
    const _material = await (new TestKeyring()).onDecrypt(material, [edk], encryptionContext)
    expect(material === _material).to.equal(true)
    expect(assertCount).to.equal(1)
  })
})

describe('Keyring: onEncrypt', () => {
  it('Precondition: material must be a type of isEncryptionMaterial.', async () => {
    let assertCount = 0
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onEncrypt (material: NodeEncryptionMaterial) {
        assertCount += 1
        return material
      }
      async _onDecrypt (material: NodeDecryptionMaterial) {
        never()
        return material
      }
    }
    const material: any = {}
    await expect((new TestKeyring()).onEncrypt(material)).to.rejectedWith(Error)
    expect(assertCount).to.equal(0)
  })

  it('Postcondition: The EncryptionMaterial objects must be the same.', async () => {
    let assertCount = 0
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onEncrypt (material: NodeEncryptionMaterial) {
        assertCount += 1
        return new NodeEncryptionMaterial(material.suite)
      }
      async _onDecrypt (material: NodeDecryptionMaterial) {
        never()
        return material
      }
    }
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const material = new NodeEncryptionMaterial(suite)
    await expect((new TestKeyring()).onEncrypt(material)).to.rejectedWith(Error)
    expect(assertCount).to.equal(1)
  })
})

describe('Keyring: onDecrypt', () => {
  it('Precondition: material must be DecryptionMaterial.', async () => {
    const material: any = {}
    const edk = new EncryptedDataKey({ providerId: 'p', providerInfo: 'i', encryptedDataKey: new Uint8Array(3) })
    let assertCount = 0
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onDecrypt (material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext */) {
        assertCount += 1
        return material
      }
      async _onEncrypt (material: NodeEncryptionMaterial) {
        never()
        return material
      }
    }
    await expect((new TestKeyring()).onDecrypt(material, [edk])).to.rejectedWith(Error)
    expect(assertCount).to.equal(0)
  })

  it('Precondition: Attempt to decrypt iif material does not have an unencrypted data key.', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const material = new NodeDecryptionMaterial(suite)
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
    material.setUnencryptedDataKey(unencryptedDataKey, trace)
    const edk = new EncryptedDataKey({ providerId: 'p', providerInfo: 'i', encryptedDataKey: new Uint8Array(3) })
    let assertCount = 0
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onDecrypt (material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext */) {
        assertCount += 1
        return material
      }
      async _onEncrypt (material: NodeEncryptionMaterial) {
        never()
        return material
      }
    }
    const _material = await (new TestKeyring()).onDecrypt(material, [edk])
    expect(assertCount).to.equal(0)
    expect(_material === material).to.equal(true)
  })

  it('Precondition: encryptedDataKeys must all be EncryptedDataKey.', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const material = new NodeDecryptionMaterial(suite)
    const edk: any = {}
    let assertCount = 0
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onDecrypt (material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext */) {
        assertCount += 1
        return material
      }
      async _onEncrypt (material: NodeEncryptionMaterial) {
        never()
        return material
      }
    }
    await expect((new TestKeyring()).onDecrypt(material, [edk])).to.rejectedWith(Error)
    expect(assertCount).to.equal(0)
  })

  it('Postcondition: The DecryptionMaterial objects must be the same.', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const material = new NodeDecryptionMaterial(suite)
    const edk = new EncryptedDataKey({ providerId: 'p', providerInfo: 'i', encryptedDataKey: new Uint8Array(3) })
    let assertCount = 0
    class TestKeyring extends Keyring<NodeAlgorithmSuite> {
      async _onDecrypt (/* material: NodeDecryptionMaterial , encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext */) {
        assertCount += 1
        const _material: any = {}
        return _material
      }
      async _onEncrypt (material: NodeEncryptionMaterial) {
        never()
        return material
      }
    }
    await expect((new TestKeyring()).onDecrypt(material, [edk])).to.rejectedWith(Error)
    expect(assertCount).to.equal(1)
  })
})
