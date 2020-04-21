// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  KmsKeyringClass,
  KeyRingConstructible // eslint-disable-line no-unused-vars
} from '../src/kms_keyring'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  NodeDecryptionMaterial,
  EncryptedDataKey,
  Keyring
} from '@aws-crypto/material-management'
chai.use(chaiAsPromised)
const { expect } = chai

describe('KmsKeyring: _onDecrypt',
  () => {
    it('returns material', async () => {
      const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
      const encryptKmsKey = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
      const keyIds = [encryptKmsKey]
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

      const clientProvider: any = () => {
        return { decrypt }
        function decrypt ({ CiphertextBlob, EncryptionContext, GrantTokens }: any) {
          expect(EncryptionContext).to.deep.equal(context)
          expect(GrantTokens).to.equal(grantTokens)
          return {
            Plaintext: new Uint8Array(suite.keyLengthBytes),
            KeyId: Buffer.from(<Uint8Array>CiphertextBlob).toString('utf8')
          }
        }
      }
      class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider,
        generatorKeyId,
        keyIds,
        grantTokens
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: generatorKeyId,
        encryptedDataKey: Buffer.from(generatorKeyId)
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        [edk]
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)

      expect(material.keyringTrace).to.have.lengthOf(1)
      const [traceDecrypt] = material.keyringTrace
      expect(traceDecrypt.keyNamespace).to.equal('aws-kms')
      expect(traceDecrypt.keyName).to.equal(generatorKeyId)
      expect(traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY).to.equal(KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
      expect(traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX).to.equal(KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX)
    })

    it('discovery keyring should return material', async () => {
      const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const discovery = true
      const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

      const clientProvider: any = () => {
        return { decrypt }
        function decrypt ({ CiphertextBlob, EncryptionContext, GrantTokens }: any) {
          expect(EncryptionContext).to.deep.equal(context)
          expect(GrantTokens).to.equal(grantTokens)
          return {
            Plaintext: new Uint8Array(suite.keyLengthBytes),
            KeyId: Buffer.from(<Uint8Array>CiphertextBlob).toString('utf8')
          }
        }
      }
      class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider,
        grantTokens,
        discovery
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: generatorKeyId,
        encryptedDataKey: Buffer.from(generatorKeyId)
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        [edk]
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)

      expect(material.keyringTrace).to.have.lengthOf(1)
      const [traceDecrypt] = material.keyringTrace
      expect(traceDecrypt.keyNamespace).to.equal('aws-kms')
      expect(traceDecrypt.keyName).to.equal(generatorKeyId)
      expect(traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY).to.equal(KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
      expect(traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX).to.equal(KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX)
    })

    it('decrypt errors should not halt', async () => {
      const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const discovery = true
      const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

      let edkCount = 0
      const clientProvider: any = () => {
        return { decrypt }
        function decrypt ({ CiphertextBlob, EncryptionContext, GrantTokens }: any) {
          if (edkCount === 0) {
            edkCount += 1
            throw new Error('failed to decrypt')
          }
          expect(EncryptionContext).to.deep.equal(context)
          expect(GrantTokens).to.equal(grantTokens)
          return {
            Plaintext: new Uint8Array(suite.keyLengthBytes),
            KeyId: Buffer.from(<Uint8Array>CiphertextBlob).toString('utf8')
          }
        }
      }
      class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider,
        grantTokens,
        discovery
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: generatorKeyId,
        encryptedDataKey: Buffer.from(generatorKeyId)
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        [edk, edk]
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)
      expect(material.keyringTrace).to.have.lengthOf(1)
    })

    it('Check for early return (Postcondition): clientProvider may not return a client.', async () => {
      const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
      const encryptKmsKey = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
      const keyIds = [encryptKmsKey]
      const encryptionContext = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

      const clientProvider: any = () => false
      class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider,
        generatorKeyId,
        keyIds,
        grantTokens
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: generatorKeyId,
        encryptedDataKey: Buffer.from(generatorKeyId)
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, encryptionContext),
        [edk]
      )

      expect(material.hasUnencryptedDataKey).to.equal(false)
      expect(material.keyringTrace).to.have.lengthOf(0)
    })

    it('Postcondition: The KeyId from KMS must match the encoded KeyID.', async () => {
      const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
      const encryptKmsKey = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
      const keyIds = [encryptKmsKey]
      const encryptionContext = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

      const clientProvider: any = () => {
        return { decrypt }
        function decrypt ({ EncryptionContext, GrantTokens }: any) {
          expect(EncryptionContext).to.deep.equal(encryptionContext)
          expect(GrantTokens).to.equal(grantTokens)
          return {
            Plaintext: new Uint8Array(suite.keyLengthBytes),
            KeyId: 'Not the Encrypted ARN'
          }
        }
      }
      class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider,
        generatorKeyId,
        keyIds,
        grantTokens
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: generatorKeyId,
        encryptedDataKey: Buffer.from(generatorKeyId)
      })

      return expect(testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, encryptionContext),
        [edk]
      )).to.rejectedWith(Error, 'KMS Decryption key does not match serialized provider.')
    })

    it('Postcondition: The decrypted unencryptedDataKey length must match the algorithm specification.', async () => {
      const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
      const encryptKmsKey = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
      const keyIds = [encryptKmsKey]
      const encryptionContext = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

      const clientProvider: any = () => {
        return { decrypt }
        function decrypt ({ CiphertextBlob, EncryptionContext, GrantTokens }: any) {
          expect(EncryptionContext).to.deep.equal(encryptionContext)
          expect(GrantTokens).to.equal(grantTokens)
          return {
            Plaintext: new Uint8Array(suite.keyLengthBytes - 5),
            KeyId: Buffer.from(<Uint8Array>CiphertextBlob).toString('utf8')
          }
        }
      }
      class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider,
        generatorKeyId,
        keyIds,
        grantTokens
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: generatorKeyId,
        encryptedDataKey: Buffer.from(generatorKeyId)
      })

      return expect(testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, encryptionContext),
        [edk]
      )).to.rejectedWith(Error, 'Key length does not agree with the algorithm specification.')
    })

    it('Postcondition: A CMK must provide a valid data key or KMS must not have raised any errors.', async () => {
      const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const discovery = true
      const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)

      const clientProviderError: any = () => {
        return { decrypt }
        function decrypt () {
          throw new Error('failed to decrypt')
        }
      }
      class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: clientProviderError,
        grantTokens,
        discovery
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: generatorKeyId,
        encryptedDataKey: Buffer.from(generatorKeyId)
      })

      await expect(testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        [edk, edk]
      )).to.rejectedWith(Error, 'Unable to decrypt data key and one or more KMS CMKs had an error.')

      /* This will make the decrypt loop not have an error.
       * This will exercise the `(!material.hasValidKey() && !cmkErrors.length)` `needs` condition.
       */
      const clientProviderNoError: any = () => false
      await expect(new TestKmsKeyring({
        clientProvider: clientProviderNoError,
        grantTokens,
        discovery
      }).onDecrypt(new NodeDecryptionMaterial(suite, context),
        [edk, edk]
      )).to.not.rejectedWith(Error)
    })
  })
