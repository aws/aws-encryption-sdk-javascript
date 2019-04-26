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

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import 'mocha'
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
          expect(EncryptionContext === context).to.equal(true)
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
        new NodeDecryptionMaterial(suite),
        [edk],
        context
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
          expect(EncryptionContext === context).to.equal(true)
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
        new NodeDecryptionMaterial(suite),
        [edk],
        context
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

      const clientProvider: any = () => {
        return { decrypt }
        function decrypt () {
          throw new Error('failed to decrypt')
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
        new NodeDecryptionMaterial(suite),
        [edk],
        context
      )

      expect(material.hasUnencryptedDataKey).to.equal(false)
      expect(material.keyringTrace).to.have.lengthOf(0)
    })
  })
