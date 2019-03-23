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

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import 'mocha'
import { KmsKeyring } from '../src/kms_keyring'
import { NodeAlgorithmSuite, AlgorithmSuiteIdentifier, NodeEncryptionMaterial, KeyringTraceFlag } from '@aws-crypto/material-management'
import { KMS } from '../src/kms_types/KMS' // eslint-disable-line no-unused-vars
import { GenerateDataKeyInput } from '../src/kms_types/GenerateDataKeyInput' // eslint-disable-line no-unused-vars
import { EncryptInput } from '../src/kms_types/EncryptInput' // eslint-disable-line no-unused-vars
chai.use(chaiAsPromised)
const { expect } = chai

describe('KmsKeyring: _onEncrypt', () => {
  it('returns material', async () => {
    const generatorKmsKey = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const encryptKmsKey = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const kmsKeys = [encryptKmsKey]
    const context = { some: 'context' }
    const grantTokens = 'grant'
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

    const clientProvider: any = () => {
      return { generateDataKey, encrypt }
      function generateDataKey ({ KeyId, EncryptionContext, GrantTokens }: GenerateDataKeyInput) {
        expect(EncryptionContext === context).to.equal(true)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId,
          CiphertextBlob: new Uint8Array(5)
        }
      }
      function encrypt ({ KeyId, EncryptionContext, GrantTokens }: EncryptInput) {
        expect(EncryptionContext === context).to.equal(true)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          KeyId,
          CiphertextBlob: new Uint8Array(5)
        }
      }
    }
    class TestKmsKeyring extends KmsKeyring<NodeAlgorithmSuite, KMS> {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKmsKey,
      kmsKeys,
      grantTokens
    })

    const material = await testKeyring.onEncrypt(new NodeEncryptionMaterial(suite), context)

    expect(material.hasUnencryptedDataKey).to.equal(true)

    expect(material.encryptedDataKeys).to.have.lengthOf(2)
    const [edkGenerate, edkEncrypt] = material.encryptedDataKeys
    expect(edkGenerate.providerId).to.equal('aws-kms')
    expect(edkGenerate.providerInfo).to.equal(generatorKmsKey)
    expect(edkEncrypt.providerId).to.equal('aws-kms')
    expect(edkEncrypt.providerInfo).to.equal(encryptKmsKey)

    expect(material.keyringTrace).to.have.lengthOf(2)
    const [traceGenerate, traceEncrypt] = material.keyringTrace
    expect(traceGenerate.keyNamespace).to.equal('aws-kms')
    expect(traceGenerate.keyName).to.equal(generatorKmsKey)
    expect(traceGenerate.flags & KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY).to.equal(KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    expect(traceGenerate.flags & KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY).to.equal(KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    expect(traceGenerate.flags & KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX).to.equal(KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX)
    expect(traceEncrypt.keyNamespace).to.equal('aws-kms')
    expect(traceEncrypt.keyName).to.equal(encryptKmsKey)
    expect(traceEncrypt.flags & KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY).to.equal(KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    expect(traceEncrypt.flags & KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX).to.equal(KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX)
  })

  it('Precondition: A generatorKmsKey must generate if we do not have an unencrypted data key.', async () => {
    const generatorKmsKey = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const encryptKmsKey = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const kmsKeys = [encryptKmsKey]
    const context = { some: 'context' }
    const grantTokens = 'grant'
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

    const clientProvider: any = () => {
      return false
    }
    class TestKmsKeyring extends KmsKeyring<NodeAlgorithmSuite, KMS> {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKmsKey,
      kmsKeys,
      grantTokens
    })

    await expect(testKeyring.onEncrypt(new NodeEncryptionMaterial(suite), context))
      .to.rejectedWith(Error)
  })

  it('Precondition: If a generator does not exist, an unencryptedDataKey *must* already exist.', async () => {
    const encryptKmsKey = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const kmsKeys = [encryptKmsKey]
    const context = { some: 'context' }
    const grantTokens = 'grant'
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

    const clientProvider: any = () => {
      return false
    }
    class TestKmsKeyring extends KmsKeyring<NodeAlgorithmSuite, KMS> {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      kmsKeys,
      grantTokens
    })

    await expect(testKeyring.onEncrypt(new NodeEncryptionMaterial(suite), context))
      .to.rejectedWith(Error)
  })

  it('generator should encrypt if material already generated', async () => {
    const generatorKmsKey = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

    const clientProvider: any = () => {
      return { encrypt }
      function encrypt ({ KeyId }: EncryptInput) {
        return {
          KeyId,
          CiphertextBlob: new Uint8Array(5)
        }
      }
    }
    class TestKmsKeyring extends KmsKeyring<NodeAlgorithmSuite, KMS> {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKmsKey
    })

    const seedMaterial = new NodeEncryptionMaterial(suite)
      .setUnencryptedDataKey(new Uint8Array(suite.keyLengthBytes), {
        keyName: 'keyName',
        keyNamespace: 'keyNamespace',
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
      })

    const material = await testKeyring.onEncrypt(seedMaterial)

    // only setUnencryptedDataKey on seedMaterial
    expect(material.encryptedDataKeys).to.have.lengthOf(1)
    const [kmsEDK] = material.encryptedDataKeys
    expect(kmsEDK.providerId).to.equal('aws-kms')
    expect(kmsEDK.providerInfo).to.equal(generatorKmsKey)

    expect(material.keyringTrace).to.have.lengthOf(2)
    const [, kmsTrace] = material.keyringTrace
    expect(kmsTrace.keyNamespace).to.equal('aws-kms')
    expect(kmsTrace.keyName).to.equal(generatorKmsKey)
    expect(kmsTrace.flags & KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY).to.equal(KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    expect(kmsTrace.flags & KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX).to.equal(KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX)
  })

  it('clientProvider may not return a client, in this case there is not an EDK to add', async () => {
    const generatorKmsKey = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

    const clientProvider: any = () => {
      return false
    }
    class TestKmsKeyring extends KmsKeyring<NodeAlgorithmSuite, KMS> {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKmsKey
    })

    const seedMaterial = new NodeEncryptionMaterial(suite)
      .setUnencryptedDataKey(new Uint8Array(suite.keyLengthBytes), {
        keyName: 'keyName',
        keyNamespace: 'keyNamespace',
        flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
      })

    const material = await testKeyring.onEncrypt(seedMaterial)

    // only setUnencryptedDataKey on seedMaterial
    expect(material.encryptedDataKeys).to.have.lengthOf(0)
    expect(material.keyringTrace).to.have.lengthOf(1)
  })
})
