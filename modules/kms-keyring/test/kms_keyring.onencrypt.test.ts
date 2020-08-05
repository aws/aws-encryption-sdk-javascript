// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { KmsKeyringClass, KeyRingConstructible } from '../src/kms_keyring'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  NodeEncryptionMaterial,
  Keyring,
} from '@aws-crypto/material-management'
chai.use(chaiAsPromised)
const { expect } = chai

describe('KmsKeyring: _onEncrypt', () => {
  it('returns material', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const encryptKmsKey =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const keyIds = [encryptKmsKey]
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return { generateDataKey, encrypt }
      function generateDataKey({ KeyId, EncryptionContext, GrantTokens }: any) {
        expect(EncryptionContext).to.deep.equal(context)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId,
          CiphertextBlob: new Uint8Array(5),
        }
      }
      function encrypt({ KeyId, EncryptionContext, GrantTokens }: any) {
        expect(EncryptionContext).to.deep.equal(context)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          KeyId,
          CiphertextBlob: new Uint8Array(5),
        }
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as KeyRingConstructible<NodeAlgorithmSuite>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
      keyIds,
      grantTokens,
    })

    const material = await testKeyring.onEncrypt(
      new NodeEncryptionMaterial(suite, context)
    )

    expect(material.hasUnencryptedDataKey).to.equal(true)

    expect(material.encryptedDataKeys).to.have.lengthOf(2)
    const [edkGenerate, edkEncrypt] = material.encryptedDataKeys
    expect(edkGenerate.providerId).to.equal('aws-kms')
    expect(edkGenerate.providerInfo).to.equal(generatorKeyId)
    expect(edkEncrypt.providerId).to.equal('aws-kms')
    expect(edkEncrypt.providerInfo).to.equal(encryptKmsKey)
  })

  it('Check for early return (Postcondition): Discovery Keyrings do not encrypt.', async () => {
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return false
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as KeyRingConstructible<NodeAlgorithmSuite>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      discovery: true,
      grantTokens,
    })

    const material = await testKeyring.onEncrypt(
      new NodeEncryptionMaterial(suite, encryptionContext)
    )

    expect(material.hasUnencryptedDataKey).to.equal(false)
    expect(material.encryptedDataKeys).to.have.lengthOf(0)
  })

  it('Precondition: A generatorKeyId must generate if we do not have an unencrypted data key.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const encryptKmsKey =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const keyIds = [encryptKmsKey]
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return false
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as KeyRingConstructible<NodeAlgorithmSuite>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
      keyIds,
      grantTokens,
    })

    await expect(
      testKeyring.onEncrypt(new NodeEncryptionMaterial(suite, context))
    ).to.rejectedWith(Error)
  })

  it('Postcondition: The generated unencryptedDataKey length must match the algorithm specification.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return { generateDataKey }
      function generateDataKey({ KeyId, EncryptionContext, GrantTokens }: any) {
        expect(EncryptionContext).to.deep.equal(encryptionContext)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes - 5),
          KeyId,
          CiphertextBlob: new Uint8Array(5),
        }
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as KeyRingConstructible<NodeAlgorithmSuite>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
      grantTokens,
    })

    return expect(
      testKeyring.onEncrypt(
        new NodeEncryptionMaterial(suite, encryptionContext)
      )
    ).to.rejectedWith(
      Error,
      'Key length does not agree with the algorithm specification.'
    )
  })

  it('Precondition: If a generator does not exist, an unencryptedDataKey *must* already exist.', async () => {
    const encryptKmsKey =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const keyIds = [encryptKmsKey]
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return false
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as KeyRingConstructible<NodeAlgorithmSuite>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      keyIds,
      grantTokens,
    })

    await expect(
      testKeyring.onEncrypt(new NodeEncryptionMaterial(suite, context))
    ).to.rejectedWith(Error)
  })

  it('generator should encrypt if material already generated', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return { encrypt }
      function encrypt({ KeyId }: any) {
        return {
          KeyId,
          CiphertextBlob: new Uint8Array(5),
        }
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as KeyRingConstructible<NodeAlgorithmSuite>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
    })

    const seedMaterial = new NodeEncryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(suite.keyLengthBytes))

    const material = await testKeyring.onEncrypt(seedMaterial)

    // only setUnencryptedDataKey on seedMaterial
    expect(material.encryptedDataKeys).to.have.lengthOf(1)
    const [kmsEDK] = material.encryptedDataKeys
    expect(kmsEDK.providerId).to.equal('aws-kms')
    expect(kmsEDK.providerInfo).to.equal(generatorKeyId)
  })

  it('clientProvider may not return a client, in this case there is not an EDK to add', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return false
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as KeyRingConstructible<NodeAlgorithmSuite>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
    })

    const seedMaterial = new NodeEncryptionMaterial(
      suite,
      {}
    ).setUnencryptedDataKey(new Uint8Array(suite.keyLengthBytes))

    const material = await testKeyring.onEncrypt(seedMaterial)

    // only setUnencryptedDataKey on seedMaterial
    expect(material.encryptedDataKeys).to.have.lengthOf(0)
  })
})
