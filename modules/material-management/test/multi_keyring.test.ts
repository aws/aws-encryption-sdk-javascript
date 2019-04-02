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
import { MultiKeyring } from '../src/multi_keyring'
import { Keyring } from '../src/keyring'
import { NodeEncryptionMaterial, NodeDecryptionMaterial } from '../src/cryptographic_material'
import { NodeAlgorithmSuite } from '../src/node_algorithms'
import { AlgorithmSuiteIdentifier } from '../src/algorithm_suites'
import { EncryptedDataKey } from '../src/encrypted_data_key'
import { KeyringTraceFlag, KeyringTrace } from '../src/keyring_trace' // eslint-disable-line no-unused-vars

chai.use(chaiAsPromised)
const { expect } = chai

const never = async () => { throw new Error('never') }

describe('MultiKeyring: Creating', () => {
  it('can not create a noop MultiKeyring', () => {
    // @ts-ignore trying to do something that I should not do...
    expect(() => new MultiKeyring()).to.throw()
    expect(() => new MultiKeyring({})).to.throw()
  })

  it('create with generator', () => {
    const generator = keyRingFactory({ onEncrypt: never, onDecrypt: never })

    const mkeyring = new MultiKeyring({ generator })
    expect(mkeyring.children).to.be.an('Array').with.lengthOf(0)
    expect(mkeyring.generator).to.equal(generator)
  })

  it('create with generator and child', () => {
    const generator = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const child0 = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const child1 = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const children = [child0, child1]

    const mkeyring = new MultiKeyring({ generator, children })
    expect(mkeyring.children).to.be.an('Array').with.lengthOf(2)
    expect(mkeyring.generator).to.equal(generator)
    expect(mkeyring.children[0]).to.equal(child0)
    expect(mkeyring.children[1]).to.equal(child1)
  })

  it('create without generator', () => {
    const child0 = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const child1 = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const children = [child0, child1]

    const mkeyring = new MultiKeyring({ children })
    expect(mkeyring.children).to.be.an('Array').with.lengthOf(2)
    expect(mkeyring.generator).to.equal(undefined)
    expect(mkeyring.children[0]).to.equal(child0)
    expect(mkeyring.children[1]).to.equal(child1)
  })

  it('can not create with a generator that does not look like a KeyRing', () => {
    const generator: any = {}

    expect(() => new MultiKeyring({ generator })).to.throw()
  })

  it('can not create with a child that does not look like a KeyRing', () => {
    const generator = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const children = [{} as any]

    expect(() => new MultiKeyring({ generator, children })).to.throw()
  })

  it('can not create with only a child that does not look like a KeyRing', () => {
    const child0: any = {}

    expect(() => new MultiKeyring({ children: [child0] })).to.throw()
  })
})

describe('MultiKeyring: onEncrypt', () => {
  it('calls generator.onEncrypt', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0, keyringTrace0] = makeEDKandTrace(0)
    const generator = keyRingFactory({
      async onEncrypt (material: NodeEncryptionMaterial) {
        return material
          .setUnencryptedDataKey(unencryptedDataKey, keyringTrace0)
          .addEncryptedDataKey(edk0, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      },
      onDecrypt: never
    })

    const mkeyring = new MultiKeyring({ generator })
    const material = new NodeEncryptionMaterial(suite)
    const test: any = await mkeyring.onEncrypt(material)
    expect(test === material).to.equal(true)

    const edks = test.encryptedDataKeys
    expect(edks).to.be.an('Array').with.lengthOf(1)
    expect(edks[0] === edk0).to.equal(true)
    expect(test.keyringTrace).to.be.an('Array').with.lengthOf(1)
    expect(test.keyringTrace[0] === keyringTrace0).to.equal(true)

    // Make sure the unencrypted data key match
    expect(test.getUnencryptedDataKey()).to.deep.equal(unencryptedDataKey)
  })

  it('calls generator then child keyrings', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0, keyringTrace0] = makeEDKandTrace(0)
    const [edk1] = makeEDKandTrace(1)
    const generator = keyRingFactory({
      async onEncrypt (material: NodeEncryptionMaterial) {
        return material
          .setUnencryptedDataKey(unencryptedDataKey, keyringTrace0)
          .addEncryptedDataKey(edk0, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      },
      onDecrypt: never
    })
    const children = [
      keyRingFactory({
        async onEncrypt (material: NodeEncryptionMaterial) {
          return material.addEncryptedDataKey(edk1, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
        },
        onDecrypt: never
      })
    ]

    const mkeyring = new MultiKeyring({ generator, children })
    const material = new NodeEncryptionMaterial(suite)
    const test: any = await mkeyring.onEncrypt(material)
    expect(test === material).to.equal(true)

    const edks = test.encryptedDataKeys
    expect(edks).to.be.an('Array').with.lengthOf(2)
    expect(edks[0] === edk0).to.equal(true)
    expect(edks[1] === edk1).to.equal(true)
    expect(test.keyringTrace).to.be.an('Array').with.lengthOf(2)

    // Make sure the unencrypted data key match
    expect(test.getUnencryptedDataKey()).to.deep.equal(unencryptedDataKey)
  })

  it('Precondition: A Generator Keyring *must* ensure generated material.', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const [, keyringTrace0] = makeEDKandTrace(0)
    const generator = keyRingFactory({
      async onEncrypt (material: NodeEncryptionMaterial) {
        material.keyringTrace.push(keyringTrace0)
        return material
      },
      onDecrypt: never
    })

    const mkeyring = new MultiKeyring({ generator })
    const material = new NodeEncryptionMaterial(suite)

    await expect(mkeyring.onEncrypt(material)).to.rejectedWith(Error)
  })

  it('Generator Keyrings do not *have* to generate material if material already exists', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0, keyringTrace0] = makeEDKandTrace(0)
    const generator = keyRingFactory({
      async onEncrypt (material: NodeEncryptionMaterial) {
        return material.addEncryptedDataKey(edk0, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      },
      onDecrypt: never
    })

    const mkeyring = new MultiKeyring({ generator })
    const material = new NodeEncryptionMaterial(suite).setUnencryptedDataKey(unencryptedDataKey, keyringTrace0)

    await mkeyring.onEncrypt(material)
  })
})

describe('MultiKeyring: onDecrypt', () => {
  it('calls generator.onDecrypt', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0, keyringTrace0] = makeEDKandTrace(0)
    const material = new NodeDecryptionMaterial(suite)

    const generator = keyRingFactory({
      async onDecrypt (material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext */) {
        return material.setUnencryptedDataKey(unencryptedDataKey, keyringTrace0)
      },
      onEncrypt: never
    })

    const mkeyring = new MultiKeyring({ generator })

    const test: any = await mkeyring.onDecrypt(material, [edk0])
    expect(test === material).to.equal(true)
    expect(test.keyringTrace).to.be.an('Array').with.lengthOf(1)
    expect(test.keyringTrace[0] === keyringTrace0).to.equal(true)

    // Make sure the unencrypted data key match
    expect(test.getUnencryptedDataKey()).to.deep.equal(unencryptedDataKey)
  })

  it('calls children.onDecrypt', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0, keyringTrace0] = makeEDKandTrace(0)
    const material = new NodeDecryptionMaterial(suite)

    const child = keyRingFactory({
      async onDecrypt (material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext */) {
        return material.setUnencryptedDataKey(unencryptedDataKey, keyringTrace0)
      },
      onEncrypt: never
    })

    const mkeyring = new MultiKeyring({ children: [child] })

    const test: any = await mkeyring.onDecrypt(material, [edk0])
    expect(test === material).to.equal(true)
    expect(test.keyringTrace).to.be.an('Array').with.lengthOf(1)
    expect(test.keyringTrace[0] === keyringTrace0).to.equal(true)

    // Make sure the unencrypted data key match
    expect(test.getUnencryptedDataKey()).to.deep.equal(unencryptedDataKey)
  })

  it('does not call subsequent Keyrings after receiving DecryptionMaterial', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0, keyringTrace0] = makeEDKandTrace(0)
    const material = new NodeDecryptionMaterial(suite)

    const child = keyRingFactory({
      async onDecrypt (material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext */) {
        return material.setUnencryptedDataKey(unencryptedDataKey, keyringTrace0)
      },
      onEncrypt: never
    })

    let notCalled = true
    const childNotCalled = keyRingFactory({
      async onDecrypt () {
        notCalled = false
      },
      onEncrypt: never
    })
    const children = [child, childNotCalled]

    const mkeyring = new MultiKeyring({ children })

    const test: any = await mkeyring.onDecrypt(material, [edk0])
    expect(test === material).to.equal(true)
    expect(test.keyringTrace).to.be.an('Array').with.lengthOf(1)
    expect(test.keyringTrace[0] === keyringTrace0).to.equal(true)

    // Make sure the unencrypted data key match
    expect(test.getUnencryptedDataKey()).to.deep.equal(unencryptedDataKey)
    expect(notCalled).to.equal(true)
  })

  it('will call subsequent Keyrings after errors', async () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0, keyringTrace0] = makeEDKandTrace(0)
    const material = new NodeDecryptionMaterial(suite)

    const child = keyRingFactory({
      async onDecrypt (material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext */) {
        return material.setUnencryptedDataKey(unencryptedDataKey, keyringTrace0)
      },
      onEncrypt: never
    })

    let called = false
    const childNotSucceded = keyRingFactory({
      async onDecrypt () {
        called = true
      },
      onEncrypt: never
    })
    const children = [childNotSucceded, child]

    const mkeyring = new MultiKeyring({ children })

    const test: any = await mkeyring.onDecrypt(material, [edk0])
    expect(test === material).to.equal(true)
    expect(test.keyringTrace).to.be.an('Array').with.lengthOf(1)
    expect(test.keyringTrace[0] === keyringTrace0).to.equal(true)

    // Make sure the unencrypted data key match
    expect(test.getUnencryptedDataKey()).to.deep.equal(unencryptedDataKey)
    expect(called).to.equal(true)
  })
})

function makeEDKandTrace (num: number): [EncryptedDataKey, KeyringTrace] {
  const providerId = 'providerId' + num
  const providerInfo = 'providerInfo' + num
  const encryptedDataKey = new Uint8Array([0, 0, 0]).fill(num)
  const edk = new EncryptedDataKey({ providerId, providerInfo, encryptedDataKey })
  const flags = KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY | KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
  const keyringTrace = {
    keyNamespace: providerId,
    keyName: providerInfo,
    flags
  }
  return [edk, keyringTrace]
}

type factoryOp = {onEncrypt: any, onDecrypt: any}
function keyRingFactory ({ onEncrypt, onDecrypt }: factoryOp): Keyring<NodeAlgorithmSuite> {
  return new (class extends Keyring<NodeAlgorithmSuite> {
    _onEncrypt (...args: any[]) {
      return onEncrypt.call(this, ...args)
    }
    _onDecrypt (...args: any[]) {
      return onDecrypt.call(this, ...args)
    }
  })()
}
