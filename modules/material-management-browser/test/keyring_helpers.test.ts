// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  importCryptoKeyToMaterial,
  importForWebCryptoEncryptionMaterial,
  importForWebCryptoDecryptionMaterial,
} from '../src/index'
import {
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
} from '@aws-crypto/material-management'
import { synchronousRandomValues } from '@aws-crypto/web-crypto-backend'

chai.use(chaiAsPromised)
const { expect } = chai

describe('importCryptoKeyToMaterial', () => {
  it('adds a cryptoKey', async () => {
    const material = getWebCryptoEncryptionMaterial()

    await importCryptoKeyToMaterial(material)
    expect(material.hasCryptoKey).to.equal(true)
  })
})

describe('importForWebCryptoEncryptionMaterial', () => {
  it('adds a cryptoKey to Encryption Material', async () => {
    const material = getWebCryptoEncryptionMaterial()

    await importForWebCryptoEncryptionMaterial(material)
    expect(material.hasCryptoKey).to.equal(true)
  })

  it('Check for early return (Postcondition): If a cryptoKey has already been imported for encrypt, return.', async () => {
    const material = getWebCryptoEncryptionMaterial()

    await importForWebCryptoEncryptionMaterial(material)
    const cryptoKey = material.getCryptoKey()
    /* This is as good as it gets I think.
     * There are several protections to keep the cryptoKey from changing.
     * But these methods should throw.
     */
    await importForWebCryptoEncryptionMaterial(material)
    expect(material.getCryptoKey() === cryptoKey).to.equal(true)
  })
})

describe('importForWebCryptoDecryptionMaterial', () => {
  it('adds a cryptoKey to decryption material, and zeroes out the unencrypted data key.', async () => {
    const material = getWebCryptoDecryptionMaterial()

    await importForWebCryptoDecryptionMaterial(material)
    expect(material.hasCryptoKey).to.equal(true)
    expect(material.hasUnencryptedDataKey).to.equal(false)
  })

  it('Check for early return (Postcondition): If a cryptoKey has already been imported for decrypt, return.', async () => {
    const material = getWebCryptoDecryptionMaterial()

    await importForWebCryptoDecryptionMaterial(material)
    const cryptoKey = material.getCryptoKey()
    /* This is as good as it gets I think.
     * There are several protections to keep the cryptoKey from changing.
     * But these methods should throw.
     */
    await importForWebCryptoDecryptionMaterial(material)
    expect(material.getCryptoKey() === cryptoKey).to.equal(true)
  })

  it('Check for early return (Postcondition): If no key was able to be decrypted, return.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const material = new WebCryptoDecryptionMaterial(suite, {})

    await importForWebCryptoDecryptionMaterial(material)
    expect(material.hasCryptoKey).to.equal(false)
  })
})

function getWebCryptoDecryptionMaterial() {
  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
  )
  const material = new WebCryptoDecryptionMaterial(suite, {})
  const udk = synchronousRandomValues(suite.keyLengthBytes)
  const trace = {
    keyName: 'keyName',
    keyNamespace: 'keyNamespace',
    flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
  }
  return material.setUnencryptedDataKey(udk, trace)
}

function getWebCryptoEncryptionMaterial() {
  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
  )
  const material = new WebCryptoEncryptionMaterial(suite, {})
  const udk = synchronousRandomValues(suite.keyLengthBytes)
  const trace = {
    keyName: 'keyName',
    keyNamespace: 'keyNamespace',
    flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
  }
  return material.setUnencryptedDataKey(udk, trace)
}
