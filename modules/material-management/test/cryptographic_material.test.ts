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

import { expect } from 'chai'
import 'mocha'
import {EncryptedDataKey, NodeAlgorithmSuite, AlgorithmSuiteIdentifier, SignatureKey, VerificationKey, WebCryptoAlgorithmSuite} from '../src'

import {decorateCryptographicMaterial, decorateEncryptionMaterial, decorateDecryptionMaterial, decorateWebCryptoMaterial, NodeEncryptionMaterial, NodeDecryptionMaterial, WebCryptoEncryptionMaterial, WebCryptoDecryptionMaterial} from '../src/cryptographic_material'

describe('decorateCryptographicMaterial', () => {
  it('will decorate', () => {
    const test = decorateCryptographicMaterial((<any>{}))
    expect(test).to.haveOwnProperty('setUnencryptedDataKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('getUnencryptedDataKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('zeroUnencryptedDataKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('hasUnencryptedDataKey').and.to.equal(false)
  })

  it('set, inspect, get works', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{suite}))
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(dataKey)
    expect(test.hasUnencryptedDataKey).to.equal(true)
    expect(test.unencryptedDataKeyLength).to.equal(dataKey.byteLength)
    expect(test.getUnencryptedDataKey()).to.deep.equal(dataKey)
  })

  it('zeroing out the unencrypted data key', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{suite}))
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(dataKey)
    test.zeroUnencryptedDataKey()
    expect(test.hasUnencryptedDataKey).to.equal(false)
    expect(dataKey).to.deep.equal(new Uint8Array(suite.keyLengthBytes).fill(0))
  })

  it('Precondition: The data key\'s length must agree with algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{suite}))
    const dataKey = new Uint8Array(suite.keyLengthBytes - 1).fill(1)
    expect(() => test.setUnencryptedDataKey(dataKey)).to.throw()
  })

  it('Precondition: unencryptedDataKey must not be Zeroed out.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{suite}))
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(dataKey)
    test.zeroUnencryptedDataKey()
    expect(() => test.getUnencryptedDataKey()).to.throw()
    expect(() => test.unencryptedDataKeyLength).to.throw()
  })

  it('Precondition: unencryptedDataKey must be set before we can return it.', () => {
    const test: any = decorateCryptographicMaterial((<any>{}))
    expect(() => test.getUnencryptedDataKey()).to.throw()
  })

  it('Precondition: The unencryptedDataKey must be set to have a length.', () => {
    const test: any = decorateCryptographicMaterial((<any>{}))
    expect(() => test.unencryptedDataKeyLength).to.throw()
  })

  it('Precondition: The unencryptedDataKey must be set to be zeroed.', () => {
    const test: any = decorateCryptographicMaterial((<any>{}))
    expect(() => test.zeroUnencryptedDataKey()).to.throw()
  })

  it('Precondition: unencryptedDataKey must not be set.  Modifying the unencryptedDataKey is denied', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{suite}))
    expect(() => test.setUnencryptedDataKey('')).to.throw()
  })

  it('Precondition: unencryptedDataKey must not be set.  Modifying the unencryptedDataKey is denied', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test = decorateCryptographicMaterial((<any>{suite}))
    const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
    test.setUnencryptedDataKey(dataKey)
    expect(() => test.setUnencryptedDataKey(dataKey)).to.throw()
  })
})

describe('decorateEncryptionMaterial', () => {
  it('will decorate', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test: any = decorateEncryptionMaterial((<any>{suite}))
    expect(test).to.haveOwnProperty('addEncryptedDataKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('setSignatureKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('encryptedDataKeys').and.to.be.a('array').with.lengthOf(0)
    expect(test).to.haveOwnProperty('signatureKey').and.to.equal(undefined)
  })

  it('add EncryptedDataKey', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test: any = decorateEncryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    const edk = new EncryptedDataKey({providerId: 'p', providerInfo: 'p', encryptedDataKey: new Uint8Array(3)})
    test.addEncryptedDataKey(edk)
    expect(test.encryptedDataKeys).to.have.length(1)
    expect(test.encryptedDataKeys[0] === edk).to.equal(true)
  })

  it('add SignatureKey', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateEncryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    const key = new SignatureKey(new Uint8Array(3), new Uint8Array(3))
    test.setSignatureKey(key)
    expect(test.signatureKey === key).to.equal(true)
  })

  it('Precondition: If a data key has not already been generated, there must be no EDKs.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const edk = new EncryptedDataKey({providerId: 'p', providerInfo: 'p', encryptedDataKey: new Uint8Array(3)})
    const test: any = decorateEncryptionMaterial((<any>{suite, hasUnencryptedDataKey: false}))
    expect(() => test.addEncryptedDataKey(edk)).to.throw()
  })

  it('Precondition: All edk\'s must be EncryptedDataKey', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const edk: any  = {}
    const test: any = decorateEncryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    expect(() => test.addEncryptedDataKey(edk)).to.throw()
  })

  it('Precondition: The SignatureKey stored must agree with the algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const key = new SignatureKey(new Uint8Array(3), new Uint8Array(3))
    const test: any = decorateEncryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: signatureKey must not be set.  Modifying the signatureKey is denied.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const key = new SignatureKey(new Uint8Array(3), new Uint8Array(3))
    const test: any = decorateEncryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    test.setSignatureKey(key)
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: key must be a SignatureKey.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const key : any = {}
    const test: any = decorateEncryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    expect(() => test.setSignatureKey(key)).to.throw()
  })

  it('Precondition: The SignatureKey gotten must agree with the algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateEncryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    expect(() => test.signatureKey).to.throw()
  })
})

describe('decorateDecryptionMaterial', () => {
  it('will decorate', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const test: any = decorateDecryptionMaterial((<any>{suite}))
    expect(test).to.haveOwnProperty('setVerificationKey').and.to.be.a('function')
    expect(test).to.haveOwnProperty('verificationKey').and.to.equal(undefined)
  })

  it('add VerificationKey', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateDecryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    const key = new VerificationKey(new Uint8Array(3))
    test.setVerificationKey(key)
    expect(test.verificationKey === key).to.equal(true)
  })

  it('Precondition: The VerificationKey stored must agree with the algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    const key = new VerificationKey(new Uint8Array(3))
    const test: any = decorateDecryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: verificationKey must not be set.  Modifying the verificationKey is denied.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const key = new VerificationKey(new Uint8Array(3))
    const test: any = decorateDecryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    test.setVerificationKey(key)
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: key must be a VerificationKey.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const key : any = {}
    const test: any = decorateDecryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    expect(() => test.setVerificationKey(key)).to.throw()
  })

  it('Precondition: The VerificationKey gotten must agree with the algorithm specification.', () => {
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const test: any = decorateDecryptionMaterial((<any>{suite, hasUnencryptedDataKey: true}))
    expect(() => test.verificationKey).to.throw()
  })
})

describe('decorateWebCryptoMaterial', () => {
  it('will decorate', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}))
    expect(test).to.haveOwnProperty('setCryptoKey').and.to.be.a('function')
  })

  it('add CryptoKey', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}))
    const key: any = {algorithm: true}
    test.setCryptoKey(key)
    expect(test.cryptoKey === key).to.equal(true)
  })

  it('add MixedBackendCryptoKey', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}))
    const key: any = {zeroByteCryptoKey: {algorithm: true}, nonZeroByteCryptoKey: {algorithm: true}}
    test.setCryptoKey(key)
    expect(test.cryptoKey !== key).to.equal(true)
    expect(test.cryptoKey.zeroByteCryptoKey === key.zeroByteCryptoKey).to.equal(true)
    expect(test.cryptoKey.nonZeroByteCryptoKey === key.nonZeroByteCryptoKey).to.equal(true)
    expect(Object.isFrozen(test.cryptoKey)).to.equal(true)
  })

  it('Precondition: The cryptoKey must be set before we can return it.', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}))
    expect(() => test.cryptoKey).to.throw()
  })

  it('Precondition: cryptoKey must not be set.  Modifying the cryptoKey is denied', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}))
    const key: any = {algorithm: true}
    test.setCryptoKey(key)
    expect(() => test.setCryptoKey(key)).to.throw()
  })

  it('Precondition: The CryptoKey must not be extractable.', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}))
    const key: any = {algorithm: true, extractable: true}
    expect(() => test.setCryptoKey(key)).to.throw()
  })

  it('Precondition: The CryptoKey\'s inside MixedBackendCryptoKey must not be extractable.', () => {
    const test: any = decorateWebCryptoMaterial((<any>{}))
    const key1: any = {zeroByteCryptoKey: {algorithm: true, extractable: true}, nonZeroByteCryptoKey: {algorithm: true}}
    const key2: any = {zeroByteCryptoKey: {algorithm: true}, nonZeroByteCryptoKey: {algorithm: true, extractable: true}}
    expect(() => test.setCryptoKey(key1)).to.throw()
    expect(() => test.setCryptoKey(key2)).to.throw()
  })
})

describe('NodeEncryptionMaterial', () => {
  const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
  const test: any = new NodeEncryptionMaterial(suite)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(NodeAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(NodeAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: suite is NodeAlgorithmSuite', () => {
    const suite: any = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => new NodeEncryptionMaterial(suite)).to.throw()
  })
})

describe('NodeDecryptionMaterial', () => {
  const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
  const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
  const test: any = new NodeDecryptionMaterial(suite, unencryptedDataKey)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(NodeAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(NodeAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: suite is NodeAlgorithmSuite', () => {
    const suite: any = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => new NodeDecryptionMaterial(suite, unencryptedDataKey)).to.throw()
  })
})

describe('WebCryptoEncryptionMaterial', () => {
  const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
  const test: any = new WebCryptoEncryptionMaterial(suite)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(WebCryptoAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(WebCryptoAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: suite is NodeAlgorithmSuite', () => {
    const suite: any = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => new WebCryptoEncryptionMaterial(suite)).to.throw()
  })
})

describe('WebCryptoDecryptionMaterial', () => {
  const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
  const unencryptedDataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
  const test: any = new WebCryptoDecryptionMaterial(suite, unencryptedDataKey)
  it('instance is frozen', () => expect(Object.isFrozen(test)).to.equal(true))
  it('has a suite', () => expect(test.suite === suite).to.equal(true))
  it('class is frozen', () => expect(Object.isFrozen(WebCryptoAlgorithmSuite)).to.equal(true))
  it('class prototype is frozen', () => expect(Object.isFrozen(WebCryptoAlgorithmSuite.prototype)).to.equal(true))
  it('Precondition: suite is NodeAlgorithmSuite', () => {
    const suite: any = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => new WebCryptoDecryptionMaterial(suite, unencryptedDataKey)).to.throw()
  })
})
