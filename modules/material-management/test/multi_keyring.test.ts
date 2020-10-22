// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { MultiKeyringNode } from '../src/multi_keyring'
import { KeyringNode, KeyringWebCrypto } from '../src/keyring'
import {
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  unwrapDataKey,
} from '../src/cryptographic_material'
import { NodeAlgorithmSuite } from '../src/node_algorithms'
import { AlgorithmSuiteIdentifier } from '../src/algorithm_suites'
import { EncryptedDataKey } from '../src/encrypted_data_key'

chai.use(chaiAsPromised)
const { expect } = chai

const never = async () => {
  throw new Error('never')
}

describe('MultiKeyring: Creating', () => {
  it('Precondition: MultiKeyring must have keyrings.', () => {
    // @ts-ignore trying to do something that I should not do...
    expect(() => new MultiKeyringNode()).to.throw()
    expect(() => new MultiKeyringNode({})).to.throw()
  })

  it('create with generator', () => {
    const generator = keyRingFactory({ onEncrypt: never, onDecrypt: never })

    const mkeyring = new MultiKeyringNode({ generator })
    expect(mkeyring.children).to.be.an('Array').with.lengthOf(0)
    expect(mkeyring.generator).to.equal(generator)
  })

  it('create with generator and child', () => {
    const generator = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const child0 = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const child1 = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const children = [child0, child1]

    const mkeyring = new MultiKeyringNode({ generator, children })
    expect(mkeyring.children).to.be.an('Array').with.lengthOf(2)
    expect(mkeyring.generator).to.equal(generator)
    expect(mkeyring.children[0]).to.equal(child0)
    expect(mkeyring.children[1]).to.equal(child1)
  })

  it('create without generator', () => {
    const child0 = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const child1 = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const children = [child0, child1]

    const mkeyring = new MultiKeyringNode({ children })
    expect(mkeyring.children).to.be.an('Array').with.lengthOf(2)
    expect(mkeyring.generator).to.equal(undefined)
    expect(mkeyring.children[0]).to.equal(child0)
    expect(mkeyring.children[1]).to.equal(child1)
  })

  it('Precondition: generator must be a Keyring.', () => {
    expect(() => new MultiKeyringNode({ generator: {} as any })).to.throw()

    const testClass = new (class extends KeyringWebCrypto {
      _onEncrypt() {
        return {} as any
      }
      _onDecrypt() {
        return {} as any
      }
    })()

    expect(
      () => new MultiKeyringNode({ generator: testClass as any })
    ).to.throw()
  })

  it('can not create with a child that does not look like a KeyRing', () => {
    const generator = keyRingFactory({ onEncrypt: never, onDecrypt: never })
    const children = [{} as any]

    expect(() => new MultiKeyringNode({ generator, children })).to.throw()
  })

  it('Precondition: All children must be Keyrings.', () => {
    expect(() => new MultiKeyringNode({ children: [{} as any] })).to.throw()

    const testClass = new (class extends KeyringWebCrypto {
      _onEncrypt() {
        return {} as any
      }
      _onDecrypt() {
        return {} as any
      }
    })()

    expect(
      () => new MultiKeyringNode({ children: [testClass as any] })
    ).to.throw()
  })
})

describe('MultiKeyring: onEncrypt', () => {
  it('calls generator.onEncrypt', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0] = makeEDKForEncrypt(0)
    const generator = keyRingFactory({
      async onEncrypt(material: NodeEncryptionMaterial) {
        return material
          .setUnencryptedDataKey(new Uint8Array(unencryptedDataKey))
          .addEncryptedDataKey(edk0)
      },
      onDecrypt: never,
    })

    const mkeyring = new MultiKeyringNode({ generator })
    const material = new NodeEncryptionMaterial(suite, {})
    const test: any = await mkeyring.onEncrypt(material)
    expect(test === material).to.equal(true)

    const edks = test.encryptedDataKeys
    expect(edks).to.be.an('Array').with.lengthOf(1)
    expect(edks[0] === edk0).to.equal(true)

    // Make sure the unencrypted data key match
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(
      unencryptedDataKey
    )
  })

  it('calls generator then child keyrings', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0] = makeEDKForEncrypt(0)
    const [edk1] = makeEDKForEncrypt(1)
    const generator = keyRingFactory({
      async onEncrypt(material: NodeEncryptionMaterial) {
        return material
          .setUnencryptedDataKey(new Uint8Array(unencryptedDataKey))
          .addEncryptedDataKey(edk0)
      },
      onDecrypt: never,
    })
    const children = [
      keyRingFactory({
        async onEncrypt(material: NodeEncryptionMaterial) {
          return material.addEncryptedDataKey(edk1)
        },
        onDecrypt: never,
      }),
    ]

    const mkeyring = new MultiKeyringNode({ generator, children })
    const material = new NodeEncryptionMaterial(suite, {})
    const test: any = await mkeyring.onEncrypt(material)
    expect(test === material).to.equal(true)

    const edks = test.encryptedDataKeys
    expect(edks).to.be.an('Array').with.lengthOf(2)
    expect(edks[0] === edk0).to.equal(true)
    expect(edks[1] === edk1).to.equal(true)

    // Make sure the unencrypted data key match
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(
      unencryptedDataKey
    )
  })

  it('Precondition: A Generator Keyring *must* generated material.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const [,] = makeEDKForEncrypt(0)
    const generator = keyRingFactory({
      async onEncrypt(material: NodeEncryptionMaterial) {
        return material
      },
      onDecrypt: never,
    })

    const mkeyring = new MultiKeyringNode({ generator })
    const material = new NodeEncryptionMaterial(suite, {})

    await expect(mkeyring.onEncrypt(material)).to.rejectedWith(
      Error,
      'Generator keyring did not generated material.'
    )
  })

  it('Precondition: Keyrings not designated as generators *must not* generate material.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const child = keyRingFactory({
      async onEncrypt(material: NodeEncryptionMaterial) {
        return material
      },
      onDecrypt: never,
    })

    const mkeyring = new MultiKeyringNode({ children: [child] })
    const material = new NodeEncryptionMaterial(suite, {})
    return expect(mkeyring.onEncrypt(material)).to.rejectedWith(
      Error,
      'No data key provided and no generator defined.'
    )
  })

  it('Precondition: Keyrings designated as generators *must* generate material.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0] = makeEDKForEncrypt(0)
    const generator = keyRingFactory({
      async onEncrypt(material: NodeEncryptionMaterial) {
        return material.addEncryptedDataKey(edk0)
      },
      onDecrypt: never,
    })

    const mkeyring = new MultiKeyringNode({ generator })
    const material = new NodeEncryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(unencryptedDataKey))

    return expect(mkeyring.onEncrypt(material)).to.rejectedWith(
      Error,
      'Data key already generated.'
    )
  })

  it('If material already exists, you do not need a generator.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0] = makeEDKForEncrypt(0)
    const child = keyRingFactory({
      async onEncrypt(material: NodeEncryptionMaterial) {
        return material.addEncryptedDataKey(edk0)
      },
      onDecrypt: never,
    })

    const mkeyring = new MultiKeyringNode({ children: [child] })
    const material = new NodeEncryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(unencryptedDataKey))

    await mkeyring.onEncrypt(material)
  })
})

describe('MultiKeyring: onDecrypt', () => {
  it('calls generator.onDecrypt', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0] = makeEDKForDecrypt(0)
    const material = new NodeDecryptionMaterial(suite, {})

    const generator = keyRingFactory({
      async onDecrypt(
        material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[] */
      ) {
        return material.setUnencryptedDataKey(
          new Uint8Array(unencryptedDataKey)
        )
      },
      onEncrypt: never,
    })

    const mkeyring = new MultiKeyringNode({ generator })

    const test: any = await mkeyring.onDecrypt(material, [edk0])
    expect(test === material).to.equal(true)

    // Make sure the unencrypted data key match
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(
      unencryptedDataKey
    )
  })

  it('calls children.onDecrypt', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0] = makeEDKForDecrypt(0)
    const material = new NodeDecryptionMaterial(suite, {})

    const child = keyRingFactory({
      async onDecrypt(
        material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[] */
      ) {
        return material.setUnencryptedDataKey(
          new Uint8Array(unencryptedDataKey)
        )
      },
      onEncrypt: never,
    })

    const mkeyring = new MultiKeyringNode({ children: [child] })

    const test: any = await mkeyring.onDecrypt(material, [edk0])
    expect(test === material).to.equal(true)

    // Make sure the unencrypted data key match
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(
      unencryptedDataKey
    )
  })

  it('Check for early return (Postcondition): Do not attempt to decrypt once I have a valid key.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0] = makeEDKForDecrypt(0)
    const material = new NodeDecryptionMaterial(suite, {})

    const child = keyRingFactory({
      async onDecrypt(
        material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[] */
      ) {
        return material.setUnencryptedDataKey(
          new Uint8Array(unencryptedDataKey)
        )
      },
      onEncrypt: never,
    })

    let notCalled = true
    const childNotCalled = keyRingFactory({
      async onDecrypt() {
        notCalled = false
      },
      onEncrypt: never,
    })
    const children = [child, childNotCalled]

    const mkeyring = new MultiKeyringNode({ children })

    const test: any = await mkeyring.onDecrypt(material, [edk0])
    expect(test === material).to.equal(true)

    // Make sure the unencrypted data key match
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(
      unencryptedDataKey
    )
    expect(notCalled).to.equal(true)
  })

  it('will call subsequent Keyrings after errors', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes)
    const [edk0] = makeEDKForDecrypt(0)
    const material = new NodeDecryptionMaterial(suite, {})

    const child = keyRingFactory({
      async onDecrypt(
        material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[] */
      ) {
        return material.setUnencryptedDataKey(
          new Uint8Array(unencryptedDataKey)
        )
      },
      onEncrypt: never,
    })

    let called = false
    const childNotSucceeded = keyRingFactory({
      async onDecrypt() {
        // Because this keyring does not return a value, it will result in an error
        called = true
      },
      onEncrypt: never,
    })
    const children = [childNotSucceeded, child]

    const mkeyring = new MultiKeyringNode({ children })

    const test: any = await mkeyring.onDecrypt(material, [edk0])
    expect(test === material).to.equal(true)

    // Make sure the unencrypted data key match
    expect(unwrapDataKey(test.getUnencryptedDataKey())).to.deep.equal(
      unencryptedDataKey
    )
    expect(called).to.equal(true)
  })

  it('Postcondition: A child keyring must provide a valid data key or no child keyring must have raised an error.', async () => {
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const [edk0] = makeEDKForDecrypt(0)
    const material = new NodeDecryptionMaterial(suite, {})
    const childNotSucceeded = keyRingFactory({
      async onDecrypt() {
        // Because this keyring does not return a value, it will result in an error
      },
      onEncrypt: never,
    })
    const children = [childNotSucceeded]

    const mkeyring = new MultiKeyringNode({ children })

    await expect(mkeyring.onDecrypt(material, [edk0])).to.rejectedWith(
      Error,
      'Unable to decrypt data key and one or more child keyrings had an error.'
    )

    /* This will make the decrypt loop not have an error.
     * This will exercise the `(!material.hasValidKey() && !childKeyringErrors.length)` `needs` condition.
     */
    const childNoDataKey = keyRingFactory({
      async onDecrypt(
        material: NodeDecryptionMaterial /*, encryptedDataKeys: EncryptedDataKey[] */
      ) {
        return material
      },
      onEncrypt: never,
    })

    const mkeyringNoErrors = new MultiKeyringNode({
      children: [childNoDataKey],
    })

    await expect(
      mkeyringNoErrors.onDecrypt(material, [edk0])
    ).to.not.rejectedWith(Error)
  })
})

function makeEDKForEncrypt(num: number): [EncryptedDataKey] {
  return makeEDK(num)
}

function makeEDKForDecrypt(num: number): [EncryptedDataKey] {
  return makeEDK(num)
}

function makeEDK(num: number): [EncryptedDataKey] {
  const providerId = 'providerId' + num
  const providerInfo = 'providerInfo' + num
  const encryptedDataKey = new Uint8Array([0, 0, 0]).fill(num)
  const edk = new EncryptedDataKey({
    providerId,
    providerInfo,
    encryptedDataKey,
  })

  return [edk]
}

type factoryOp = { onEncrypt: any; onDecrypt: any }
function keyRingFactory({ onEncrypt, onDecrypt }: factoryOp): KeyringNode {
  return new (class extends KeyringNode {
    _onEncrypt(...args: any[]) {
      return onEncrypt.call(this, ...args)
    }
    _onDecrypt(...args: any[]) {
      return onDecrypt.call(this, ...args)
    }
  })()
}
