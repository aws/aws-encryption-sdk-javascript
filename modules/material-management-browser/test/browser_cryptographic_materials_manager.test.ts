// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
// @ts-ignore
import chaiAsPromised from 'chai-as-promised'
import {
  WebCryptoEncryptionMaterial,
  WebCryptoDecryptionMaterial,
  WebCryptoDefaultCryptographicMaterialsManager,
  importForWebCryptoEncryptionMaterial,
  importForWebCryptoDecryptionMaterial,
} from '../src/index'
import {
  KeyringWebCrypto,
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  EncryptedDataKey,
  CommitmentPolicy,
} from '@aws-crypto/material-management'
import { ENCODED_SIGNER_KEY } from '@aws-crypto/serialize'
import { toBase64 } from '@aws-sdk/util-base64-browser'
import { synchronousRandomValues } from '@aws-crypto/web-crypto-backend'

chai.use(chaiAsPromised)
const { expect } = chai

describe('WebCryptoDefaultCryptographicMaterialsManager', () => {
  class TestKeyring extends KeyringWebCrypto {
    async _onEncrypt(): Promise<WebCryptoEncryptionMaterial> {
      throw new Error('I should never see this error')
    }
    async _onDecrypt(): Promise<WebCryptoDecryptionMaterial> {
      throw new Error('I should never see this error')
    }
  }

  it('constructor sets keyring', () => {
    const keyring = new TestKeyring()
    const test = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    expect(test).to.be.instanceOf(WebCryptoDefaultCryptographicMaterialsManager)
    expect(test).to.haveOwnPropertyDescriptor('keyring', {
      value: keyring,
      writable: false,
      enumerable: true,
      configurable: false,
    })
  })

  it('Precondition: keyrings must be a KeyringWebCrypto.', () => {
    expect(
      () => new WebCryptoDefaultCryptographicMaterialsManager({} as any)
    ).to.throw()
  })

  it('set a signatureKey and the compress point on the encryption context', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)

    const test = await cmm._initializeEncryptionMaterial(suite, {
      some: 'context',
    })

    expect(test).to.be.instanceOf(WebCryptoEncryptionMaterial)
    const { signatureKey, encryptionContext } = test
    if (!signatureKey) throw new Error('I should never see this error')

    expect(Object.keys(encryptionContext)).lengthOf(2)
    expect(encryptionContext)
      .to.have.haveOwnProperty(ENCODED_SIGNER_KEY)
      .and.to.equal(toBase64(signatureKey.compressPoint))
    expect(encryptionContext)
      .to.have.haveOwnProperty('some')
      .and.to.equal('context')
  })

  it('Check for early return (Postcondition): The WebCryptoAlgorithmSuite specification must support a signatureCurve to generate a signing key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)

    const { encryptionContext } = await cmm._initializeEncryptionMaterial(
      suite,
      { some: 'context' }
    )
    expect(Object.keys(encryptionContext)).lengthOf(1)
    expect(encryptionContext)
      .to.have.haveOwnProperty('some')
      .and.to.equal('context')
  })

  it('set a verificationKey from encryption context', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const context = {
      some: 'context',
      [ENCODED_SIGNER_KEY]: 'A29gmBT/NscB90u6npOulZQwAAiKVtoShudOm2J2sCgC',
    }

    const test = await cmm._initializeDecryptionMaterial(suite, context)
    expect(test).to.be.instanceOf(WebCryptoDecryptionMaterial)
    const { verificationKey } = test
    if (!verificationKey) throw new Error('I should never see this error')
    expect(verificationKey.signatureCurve).to.equal(suite.signatureCurve)
  })

  it('Check for early return (Postcondition): The WebCryptoAlgorithmSuite specification must support a signatureCurve to extract a verification key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const context = { some: 'context' }

    const test = await cmm._initializeDecryptionMaterial(suite, context)
    expect(test.verificationKey).to.equal(undefined)
  })

  it('Precondition: WebCryptoDefaultCryptographicMaterialsManager If the algorithm suite specification requires a signatureCurve a context must exist.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)

    await expect(cmm._initializeDecryptionMaterial(suite, {})).to.rejectedWith(
      Error
    )
  })

  it('Precondition: The context must not contain a public key for a non-signing algorithm suite.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const context = {
      some: 'context',
      [ENCODED_SIGNER_KEY]: 'A29gmBT/NscB90u6npOulZQwAAiKVtoShudOm2J2sCgC',
    }
    await expect(
      cmm._initializeDecryptionMaterial(suite, context)
    ).to.be.rejectedWith(
      Error,
      'Encryption context contains public verification key for unsigned algorithm suite.'
    )
  })

  it('Precondition: WebCryptoDefaultCryptographicMaterialsManager The context must contain the public key.', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const context = { missing: 'signer key' }

    await expect(
      cmm._initializeDecryptionMaterial(suite, context)
    ).to.rejectedWith(Error)
  })

  it('can return a encryption material', async () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(
        material: WebCryptoEncryptionMaterial
      ): Promise<WebCryptoEncryptionMaterial> {
        const udk = synchronousRandomValues(suite.keyLengthBytes)
        const trace = {
          keyName: 'keyName',
          keyNamespace: 'keyNamespace',
          flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
        }
        const edk = new EncryptedDataKey({
          providerId: ' keyNamespace',
          providerInfo: 'keyName',
          encryptedDataKey: new Uint8Array(5),
        })
        material
          .setUnencryptedDataKey(udk, trace)
          .addEncryptedDataKey(
            edk,
            KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
          )

        return importForWebCryptoEncryptionMaterial(material)
      }
      async _onDecrypt(): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context',
    }

    const material = await cmm.getEncryptionMaterials({
      suite,
      encryptionContext,
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
    })
    expect(Object.keys(material.encryptionContext)).lengthOf(2)
    if (!material.signatureKey) throw new Error('I should never see this error')
    expect(material.encryptionContext)
      .to.have.haveOwnProperty(ENCODED_SIGNER_KEY)
      .and.to.equal(toBase64(material.signatureKey.compressPoint))
    expect(material.encryptionContext)
      .to.have.haveOwnProperty('some')
      .and.to.equal('context')
  })

  it('will pick a default Algorithm Suite', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(
        material: WebCryptoEncryptionMaterial
      ): Promise<WebCryptoEncryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = {
          keyName: 'keyName',
          keyNamespace: 'keyNamespace',
          flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
        }
        const edk = new EncryptedDataKey({
          providerId: ' keyNamespace',
          providerInfo: 'keyName',
          encryptedDataKey: new Uint8Array(5),
        })
        material
          .setUnencryptedDataKey(udk, trace)
          .addEncryptedDataKey(
            edk,
            KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
          )

        return importForWebCryptoEncryptionMaterial(material)
      }
      async _onDecrypt(): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context',
    }

    const material = await cmm.getEncryptionMaterials({
      encryptionContext,
      commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
    })
    expect(Object.keys(material.encryptionContext)).lengthOf(2)
    if (!material.signatureKey) throw new Error('I should never see this error')
    expect(material.encryptionContext)
      .to.have.haveOwnProperty(ENCODED_SIGNER_KEY)
      .and.to.equal(toBase64(material.signatureKey.compressPoint))
    expect(material.encryptionContext)
      .to.have.haveOwnProperty('some')
      .and.to.equal('context')
  })

  it('Precondition: WebCryptoDefaultCryptographicMaterialsManager must reserve the ENCODED_SIGNER_KEY constant from @aws-crypto/serialize.', async () => {
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      [ENCODED_SIGNER_KEY]: 'context',
    }

    await expect(
      cmm.getEncryptionMaterials({
        encryptionContext,
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      })
    ).to.rejectedWith(Error, 'Reserved encryptionContext value')
  })

  it('Postcondition: The WebCryptoEncryptionMaterial must contain a valid dataKey.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(
        material: WebCryptoEncryptionMaterial
      ): Promise<WebCryptoEncryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = {
          keyName: 'keyName',
          keyNamespace: 'keyNamespace',
          flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
        }
        const edk = new EncryptedDataKey({
          providerId: ' keyNamespace',
          providerInfo: 'keyName',
          encryptedDataKey: new Uint8Array(5),
        })
        return material
          .setUnencryptedDataKey(udk, trace)
          .addEncryptedDataKey(
            edk,
            KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
          )
      }
      async _onDecrypt(): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context',
    }

    await expect(
      cmm.getEncryptionMaterials({
        encryptionContext,
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      })
    ).to.rejectedWith(Error)
  })

  it('Postcondition: The WebCryptoEncryptionMaterial must contain at least 1 EncryptedDataKey.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(
        material: WebCryptoEncryptionMaterial
      ): Promise<WebCryptoEncryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = {
          keyName: 'keyName',
          keyNamespace: 'keyNamespace',
          flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
        }
        material.setUnencryptedDataKey(udk, trace)

        return importForWebCryptoEncryptionMaterial(material)
      }
      async _onDecrypt(): Promise<WebCryptoDecryptionMaterial> {
        throw new Error('I should never see this error')
      }
    }

    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context',
    }

    await expect(
      cmm.getEncryptionMaterials({
        encryptionContext,
        commitmentPolicy: CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT,
      })
    ).to.rejectedWith(Error)
  })

  it('can return decryption material', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt(
        material: WebCryptoDecryptionMaterial
      ): Promise<WebCryptoDecryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = {
          keyName: 'keyName',
          keyNamespace: 'keyNamespace',
          flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
        }
        material.setUnencryptedDataKey(udk, trace)

        return importForWebCryptoDecryptionMaterial(material)
      }
    }

    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context',
      [ENCODED_SIGNER_KEY]: 'A29gmBT/NscB90u6npOulZQwAAiKVtoShudOm2J2sCgC',
    }
    const edk = new EncryptedDataKey({
      providerId: ' keyNamespace',
      providerInfo: 'keyName',
      encryptedDataKey: new Uint8Array(5),
    })

    const material = await cmm.decryptMaterials({
      suite,
      encryptionContext,
      encryptedDataKeys: [edk],
    })
    if (!material.verificationKey)
      throw new Error('I should never see this error')
    expect(material.encryptionContext).to.deep.equal(encryptionContext)
    expect(material.verificationKey.signatureCurve).to.equal(
      suite.signatureCurve
    )
  })

  it('Postcondition: The WebCryptoDecryptionMaterial must contain a valid dataKey.', async () => {
    class TestKeyring extends KeyringWebCrypto {
      async _onEncrypt(): Promise<WebCryptoEncryptionMaterial> {
        throw new Error('I should never see this error')
      }
      async _onDecrypt(
        material: WebCryptoDecryptionMaterial
      ): Promise<WebCryptoDecryptionMaterial> {
        const udk = synchronousRandomValues(material.suite.keyLengthBytes)
        const trace = {
          keyName: 'keyName',
          keyNamespace: 'keyNamespace',
          flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
        }
        /* This is intentionally trickery.
         * An unencrypted data key *without* a cryptoKey, should not be valid.
         */
        return material.setUnencryptedDataKey(udk, trace)
      }
    }

    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    )
    const keyring = new TestKeyring()
    const cmm = new WebCryptoDefaultCryptographicMaterialsManager(keyring)
    const encryptionContext = {
      some: 'context',
      [ENCODED_SIGNER_KEY]: 'A29gmBT/NscB90u6npOulZQwAAiKVtoShudOm2J2sCgC',
    }
    const edk = new EncryptedDataKey({
      providerId: ' keyNamespace',
      providerInfo: 'keyName',
      encryptedDataKey: new Uint8Array(5),
    })

    await expect(
      cmm.decryptMaterials({
        suite,
        encryptionContext,
        encryptedDataKeys: [edk],
      })
    ).to.rejectedWith(Error)
  })
})
