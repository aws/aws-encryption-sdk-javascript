/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import * as chai  from 'chai'
import chaiAsPromised from  'chai-as-promised'
chai.use(chaiAsPromised)
const {expect} = chai
import 'mocha'
import {NodeEncryptionMaterial, NodeDecryptionMaterial} from '../src/cryptographic_material'
import {AlgorithmSuiteIdentifier} from '../src/algorithm_suites'
import {NodeAlgorithmSuite} from '../src/node_algorithms'
// import {WebCryptoAlgorithmSuite} from '../src/web_crypto_algorithms'
import {EncryptedDataKey} from '../src/encrypted_data_key'
import {Keyring} from '../src/keyring'
import {DecryptionRequest} from '../src'
const never = () => {throw new Error('never')}

describe('Keyring', () => {
  it('can be extended', () => {
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onEncrypt(material: NodeEncryptionMaterial){
        return material
      }
      async _onDecrypt(){}
    }
    const test = new TestKeyring()
    expect(test).to.be.instanceOf(Keyring)
  })

  it('onEncrypt calls _onEncrypt', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const {keyLengthBytes} = suite
    const m = new NodeEncryptionMaterial(suite)
    const unencryptedDataKey = new Uint8Array(keyLengthBytes).fill(1)
    let assertCount = 0
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onEncrypt(material: NodeEncryptionMaterial) {
        expect(material.suite === suite).to.equal(true)
        expect(material.hasUnencryptedDataKey).to.equal(false)
        assertCount += 1
        return material.setUnencryptedDataKey(unencryptedDataKey)
      }
      async _onDecrypt(){never()}
    }
    const material = await (new TestKeyring()).onEncrypt(m)
    expect(material === m).to.equal(true)
    expect(assertCount).to.equal(1)
  })

  it('onDecrypt calls _onDecrypt', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const edk = new EncryptedDataKey({providerId: 'p', providerInfo: 'i', encryptedDataKey: new Uint8Array(3)})
    let assertCount = 0
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onDecrypt(request: DecryptionRequest<NodeAlgorithmSuite>){
        expect(request.suite === suite).to.equal(true)
        expect(request.encryptedDataKeys[0] === edk).to.equal(true)
        assertCount += 1
      }
      async _onEncrypt(material: NodeEncryptionMaterial){
        never()
        return material
      }
    }
    const material = await (new TestKeyring()).onDecrypt({suite, encryptedDataKeys: [edk]})
    expect(material).to.equal(undefined)
    expect(assertCount).to.equal(1)
  })
})

describe('Keyring: onEncrypt', () => {
  it('Precondition: material must be a type of isEncryptionMaterial.', async () => {
    let assertCount = 0
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onEncrypt(material: NodeEncryptionMaterial) {
        assertCount += 1
        return material
      }
      async _onDecrypt(){never()}
    }
    const material: any = {}
    await expect((new TestKeyring()).onEncrypt(material)).to.rejectedWith(Error)
    expect(assertCount).to.equal(0)
  })

  it('Postcondition: _material must be a CryptographicMaterial instance.', async () => {
    let assertCount = 0
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onEncrypt(material: NodeEncryptionMaterial) {
        assertCount += 1
        const _material: any = {suite: material.suite}
        return _material
      }
      async _onDecrypt(){never()}
    }
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const material = new NodeEncryptionMaterial(suite)
    await expect((new TestKeyring()).onEncrypt(material)).to.rejectedWith(Error)
    expect(assertCount).to.equal(1)
  })

  it('Postcondition: The material objects must be the same.', async () => {
    let assertCount = 0
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onEncrypt(material: NodeEncryptionMaterial) {
        assertCount += 1
        return new NodeEncryptionMaterial(material.suite)
      }
      async _onDecrypt(){never()}
    }
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const material = new NodeEncryptionMaterial(suite)
    await expect((new TestKeyring()).onEncrypt(material)).to.rejectedWith(Error)
    expect(assertCount).to.equal(1)
  })
})

describe('Keyring: onDecrypt', () => {
  it('Precondition: Suite must be an AlgorithmSuite.', async () => {
    const suite: any = {}
    const edk = new EncryptedDataKey({providerId: 'p', providerInfo: 'i', encryptedDataKey: new Uint8Array(3)})
    let assertCount = 0
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onDecrypt(request: DecryptionRequest<NodeAlgorithmSuite>) {
        assertCount += 1
        expect(request.suite === suite).to.equal(true)        
      }
      async _onEncrypt(material: NodeEncryptionMaterial){
        never()
        return material
      }
    }
    await expect((new TestKeyring()).onDecrypt({suite, encryptedDataKeys: [edk]})).to.rejectedWith(Error)
    expect(assertCount).to.equal(0)
  })

  it('Precondition: encryptedDataKeys must all be EncryptedDataKey.', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const edk: any = {}
    let assertCount = 0
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onDecrypt(request: DecryptionRequest<NodeAlgorithmSuite>){
        assertCount += 1
        expect(request.suite === suite).to.equal(true)        
      }
      async _onEncrypt(material: NodeEncryptionMaterial){
        never()
        return material
      }
    }
    await expect((new TestKeyring()).onDecrypt({suite, encryptedDataKeys: [edk]})).to.rejectedWith(Error)
    expect(assertCount).to.equal(0)
  })

  it('Postcondition: If an EDK was decrypted it must be DecryptionMaterial', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const edk = new EncryptedDataKey({providerId: 'p', providerInfo: 'i', encryptedDataKey: new Uint8Array(3)})
    let assertCount = 0
    class TestKeyring extends Keyring<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {
      async _onDecrypt(request: DecryptionRequest<NodeAlgorithmSuite>) {
        assertCount += 1
        expect(request.suite === suite).to.equal(true)
        const material: any = {}
        return material
      }
      async _onEncrypt(material: NodeEncryptionMaterial){
        never()
        return material
      }
    }
    await expect((new TestKeyring()).onDecrypt({suite, encryptedDataKeys: [edk]})).to.rejectedWith(Error)
    expect(assertCount).to.equal(1)
  })
})
