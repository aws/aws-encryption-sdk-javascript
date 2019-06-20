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
import {
  WebCryptoEncryptionMaterial, // eslint-disable-line no-unused-vars
  WebCryptoDecryptionMaterial, // eslint-disable-line no-unused-vars
  WebCryptoDefaultCryptographicMaterialsManager,
  importForWebCryptoEncryptionMaterial,
  importForWebCryptoDecryptionMaterial
} from '../src/index'
import { KeyringWebCrypto, WebCryptoAlgorithmSuite, AlgorithmSuiteIdentifier, KeyringTraceFlag, EncryptedDataKey } from '@aws-crypto/material-management'
import { ENCODED_SIGNER_KEY } from '@aws-crypto/serialize'
import { toBase64 } from '@aws-sdk/util-base64-browser'
import { synchronousRandomValues } from '@aws-crypto/web-crypto-backend'

chai.use(chaiAsPromised)
const { expect } = chai

describe('WebCryptoDefaultCryptographicMaterialsManager', () => {
  it('constructor sets keyring', () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const keyring = new TestKeyring()
    const test = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    expect(test).to.be.instanceOf(WebCryptoDefaultCryptographicMaterialsManager)
    expect(test).to.haveOwnPropertyDescriptor('keyring', {
      value: keyring,
      writable: false,
      enumerable: true,
      configurable: false
    })
  })

  it('Precondition: keyrings must be a KeyringWebCrypto.', () => {
    expect(() => new WebCryptoDefaultCryptographicMaterialsManager({} as any)).to.throw()
  })

  it('set a signatureKey and the compress point on the encryption context', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const material = new WebCryptoEncryptionMaterial(suite)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)

    const test = await cmm._generateSigningKeyAndUpdateEncryptionContext(material, { some: 'context' })
    expect(Object.keys(test)).lengthOf(2)

    const { signatureKey } = material
    if (!signatureKey) throw new Error('I should never see this error')

    expect(test).to.have.haveOwnProperty(ENCODED_SIGNER_KEY).and.to.equal(toBase64(signatureKey.compressPoint))
    expect(test).to.have.haveOwnProperty('some').and.to.equal('context')
  })

  it('Precondition: The algorithm suite specification must support a signatureCurve to generate a signing key.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256)
    const material = new WebCryptoEncryptionMaterial(suite)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)

    const test = await cmm._generateSigningKeyAndUpdateEncryptionContext(material, { some: 'context' })
    expect(Object.keys(test)).lengthOf(1)
    expect(test).to.have.haveOwnProperty('some').and.to.equal('context')
  })

  it('set a verificationKey from context', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const context = { some: 'context', [ENCODED_SIGNER_KEY]: 'A29gmBT/NscB90u6npOulZQwAAiKVtoShudOm2J2sCgC' }

    const test = await cmm._loadVerificationKeyFromEncryptionContext(new WebCryptoDecryptionMaterial(suite), context)
    const { verificationKey } = test
    if (!verificationKey) throw new Error('I should never see this error')
    expect(verificationKey.signatureCurve).to.equal(suite.signatureCurve)
  })

  it('Precondition: The algorithm suite specification must support a signatureCurve to extract a verification key.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const context = { some: 'context' }

    const test = await cmm._loadVerificationKeyFromEncryptionContext(new WebCryptoDecryptionMaterial(suite), context)
    expect(test.verificationKey).to.equal(undefined)
  })

  it('Precondition: WebCryptoDefaultCryptographicMaterialsManager If the algorithm suite specification requires a signatureCurve a context must exist.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)

    expect(cmm._loadVerificationKeyFromEncryptionContext(new WebCryptoDecryptionMaterial(suite), {})).to.rejectedWith(Error)
  })

  it('Precondition: WebCryptoDefaultCryptographicMaterialsManager The context must contain the public key.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const context = { missing: 'signer key' }

    expect(cmm._loadVerificationKeyFromEncryptionContext(new WebCryptoDecryptionMaterial(suite), context)).to.rejectedWith(Error)
  })

  it('can return an encryption response', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (material: WebCryptoEncryptionMaterial): Promise<WebCryptoEncryptionMaterial> {
        const udk = synchronousRandomValues(suite.keyLengthBytes)
        const trace = { keyName: 'keyName', keyNamespace: 'keyNamespace', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
        const edk = new EncryptedDataKey({ providerId: ' keyNamespace', providerInfo: 'keyName', encryptedDataKey: new Uint8Array(5) })
        material
          .setUnencryptedDataKey(udk, trace)
          .addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)

        return importForWebCryptoEncryptionMaterial(material)
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context'
    }

    const test = await cmm.getEncryptionMaterials({ suite, encryptionContext })
    expect(Object.keys(test.context)).lengthOf(2)
    if (!test.material.signatureKey) throw new Error('I should never see this error')
    expect(test.context).to.have.haveOwnProperty(ENCODED_SIGNER_KEY).and.to.equal(toBase64(test.material.signatureKey.compressPoint))
    expect(test.context).to.have.haveOwnProperty('some').and.to.equal('context')
  })

  it('will pick a default Algorithm Suite', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (material: WebCryptoEncryptionMaterial): Promise<WebCryptoEncryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = { keyName: 'keyName', keyNamespace: 'keyNamespace', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
        const edk = new EncryptedDataKey({ providerId: ' keyNamespace', providerInfo: 'keyName', encryptedDataKey: new Uint8Array(5) })
        material
          .setUnencryptedDataKey(udk, trace)
          .addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)

        return importForWebCryptoEncryptionMaterial(material)
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context'
    }

    const test = await cmm.getEncryptionMaterials({ encryptionContext })
    expect(Object.keys(test.context)).lengthOf(2)
    if (!test.material.signatureKey) throw new Error('I should never see this error')
    expect(test.context).to.have.haveOwnProperty(ENCODED_SIGNER_KEY).and.to.equal(toBase64(test.material.signatureKey.compressPoint))
    expect(test.context).to.have.haveOwnProperty('some').and.to.equal('context')
  })

  it('Postcondition: The WebCryptoEncryptionMaterial must contain a valid dataKey.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (material: WebCryptoEncryptionMaterial): Promise<WebCryptoEncryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = { keyName: 'keyName', keyNamespace: 'keyNamespace', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
        const edk = new EncryptedDataKey({ providerId: ' keyNamespace', providerInfo: 'keyName', encryptedDataKey: new Uint8Array(5) })
        return material
          .setUnencryptedDataKey(udk, trace)
          .addEncryptedDataKey(edk, KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context'
    }

    expect(cmm.getEncryptionMaterials({ encryptionContext })).to.rejectedWith(Error)
  })

  it('Postcondition: The WebCryptoEncryptionMaterial must contain at least 1 EncryptedDataKey.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (material: WebCryptoEncryptionMaterial): Promise<WebCryptoEncryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = { keyName: 'keyName', keyNamespace: 'keyNamespace', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
        material
          .setUnencryptedDataKey(udk, trace)

        return importForWebCryptoEncryptionMaterial(material)
      }
      async _onDecrypt (): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context'
    }

    expect(cmm.getEncryptionMaterials({ encryptionContext })).to.rejectedWith(Error)
  })

  it('can return a decryption response', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (material: WebCryptoDecryptionMaterial): Promise<WebCryptoDecryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = { keyName: 'keyName', keyNamespace: 'keyNamespace', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
        material
          .setUnencryptedDataKey(udk, trace)

        return importForWebCryptoDecryptionMaterial(material)
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = { some: 'context', [ENCODED_SIGNER_KEY]: 'A29gmBT/NscB90u6npOulZQwAAiKVtoShudOm2J2sCgC' }
    const edk = new EncryptedDataKey({ providerId: ' keyNamespace', providerInfo: 'keyName', encryptedDataKey: new Uint8Array(5) })

    const test = await cmm.decryptMaterials({ suite, encryptionContext, encryptedDataKeys: [edk] })
    if (!test.material.verificationKey) throw new Error('I should never see this error')
    expect(test.context).to.deep.equal(encryptionContext)
    expect(test.material.verificationKey.signatureCurve).to.equal(suite.signatureCurve)
  })

  it('Postcondition: The WebCryptoDecryptionMaterial must contain a valid dataKey.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt (): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt (material: WebCryptoDecryptionMaterial): Promise<WebCryptoDecryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = { keyName: 'keyName', keyNamespace: 'keyNamespace', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
        /* This is intentionally trickery.
         * An unencrypted data key *without* a cryptoKey, should not be valid.
         */
        return material.setUnencryptedDataKey(udk, trace)
      }
    }

    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = { some: 'context', [ENCODED_SIGNER_KEY]: 'A29gmBT/NscB90u6npOulZQwAAiKVtoShudOm2J2sCgC' }
    const edk = new EncryptedDataKey({ providerId: ' keyNamespace', providerInfo: 'keyName', encryptedDataKey: new Uint8Array(5) })

    expect(cmm.decryptMaterials({ suite, encryptionContext, encryptedDataKeys: [edk] })).to.rejectedWith(Error)
  })
})
