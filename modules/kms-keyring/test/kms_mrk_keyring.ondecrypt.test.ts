// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AwsKmsMrkAwareSymmetricKeyringClass } from '../src/kms_mrk_keyring'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  NodeDecryptionMaterial,
  EncryptedDataKey,
  Keyring,
  Newable,
} from '@aws-crypto/material-management'
chai.use(chaiAsPromised)
const { expect } = chai

describe('AwsKmsMrkAwareSymmetricKeyring: _onDecrypt', () => {
  describe('returns material', () => {
    it('for configured MRK ARN', async () => {
      const configuredKeyId =
        'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
      const keyIdOtherRegion =
        'arn:aws:kms:us-west-2:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )

      function decrypt({
        KeyId,
        CiphertextBlob,
        EncryptionContext,
        GrantTokens,
      }: any) {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
        //= type=test
        //# When calling AWS KMS Decrypt
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Decrypt.html), the keyring MUST call with a request constructed
        //# as follows:
        expect(KeyId).to.equal(configuredKeyId)
        expect(EncryptionContext).to.deep.equal(context)
        expect(GrantTokens).to.equal(grantTokens)
        expect(Buffer.from(CiphertextBlob).toString('utf8')).to.equal(
          keyIdOtherRegion
        )
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId,
        }
      }
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //= type=test
      //# To attempt to decrypt a particular encrypted data key
      //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
      //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
      //# API_Decrypt.html) with the configured AWS KMS client.
      const client: any = { decrypt }

      class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
        client,
        keyId: configuredKeyId,
        grantTokens,
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: keyIdOtherRegion,
        encryptedDataKey: Buffer.from(keyIdOtherRegion),
      })

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //= type=test
      //# OnDecrypt MUST take decryption materials (structures.md#decryption-
      //# materials) and a list of encrypted data keys
      //# (structures.md#encrypted-data-key) as input.
      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        [edk]
      )

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //= type=test
      //# If the response does satisfies these requirements then OnDecrypt MUST
      //# do the following with the response:
      expect(material.hasUnencryptedDataKey).to.equal(true)
      expect(material.keyringTrace).to.have.lengthOf(1)
      const [traceDecrypt] = material.keyringTrace
      expect(traceDecrypt.keyNamespace).to.equal('aws-kms')
      expect(traceDecrypt.keyName).to.equal(configuredKeyId)
      expect(
        traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
      ).to.equal(KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
      expect(
        traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX
      ).to.equal(KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX)
    })

    it('for configured non-MRK ARN', async () => {
      const keyId =
        'arn:aws:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab'
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )

      function decrypt({
        KeyId,
        CiphertextBlob,
        EncryptionContext,
        GrantTokens,
      }: any) {
        expect(KeyId).to.equal(keyId)
        expect(EncryptionContext).to.deep.equal(context)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId: Buffer.from(CiphertextBlob as Uint8Array).toString('utf8'),
        }
      }
      const client: any = { decrypt }

      class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
        client,
        keyId,
        grantTokens,
      })

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: keyId,
        encryptedDataKey: Buffer.from(keyId),
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        [edk]
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)

      expect(material.keyringTrace).to.have.lengthOf(1)
      const [traceDecrypt] = material.keyringTrace
      expect(traceDecrypt.keyNamespace).to.equal('aws-kms')
      expect(traceDecrypt.keyName).to.equal(keyId)
      expect(
        traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
      ).to.equal(KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
      expect(
        traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX
      ).to.equal(KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX)
    })
  })

  it('do not process any EDKs if an unencrypted data key exists.', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/1234abcd-12ab-34cd-56ef-1234567890ab'
    const context = { some: 'context' }
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const client: any = {}

    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
    })

    const seedMaterial = new NodeDecryptionMaterial(
      suite,
      context
    ).setUnencryptedDataKey(new Uint8Array(suite.keyLengthBytes), {
      keyNamespace: 'k',
      keyName: 'k',
      flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY,
    })

    // The Provider info is malformed,
    // if the keyring filters this,
    // it should throw.
    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: 'Not:an/arn',
      encryptedDataKey: Buffer.from(keyId),
    })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# If the decryption materials (structures.md#decryption-materials)
    //# already contained a valid plaintext data key OnDecrypt MUST
    //# immediately return the unmodified decryption materials
    //# (structures.md#decryption-materials).
    const material = await testKeyring.onDecrypt(seedMaterial, [edk])
    expect(material === seedMaterial).to.equal(true)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
  //= type=test
  //# For each encrypted data key in the filtered set, one at a time, the
  //# OnDecrypt MUST attempt to decrypt the data key.
  it('decrypt errors should not halt', async () => {
    const mrk =
      'arn:aws:kms:us-west-1:123456789012:key/mrk-12345678123412341234123456789012'

    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let edkCount = 0
    function decrypt({
      KeyId,
      // CiphertextBlob,
      EncryptionContext,
      GrantTokens,
    }: any) {
      if (edkCount === 0) {
        edkCount += 1
        throw new Error('failed to decrypt')
      }
      expect(EncryptionContext).to.deep.equal(context)
      expect(GrantTokens).to.equal(grantTokens)
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        KeyId,
      }
    }
    const client: any = { decrypt }

    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId: mrk,
      grantTokens,
    })

    const edk1 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: mrk,
      encryptedDataKey: Buffer.from(mrk),
    })

    const edk2 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: mrk,
      encryptedDataKey: Buffer.from(mrk),
    })

    const material = await testKeyring.onDecrypt(
      new NodeDecryptionMaterial(suite, context),
      [edk1, edk2]
    )

    expect(material.hasUnencryptedDataKey).to.equal(true)
    expect(material.keyringTrace).to.have.lengthOf(1)
  })

  describe('unexpected KMS response', () => {
    const usEastMrkArn =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const usWestMrkArn =
      'arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123412341234123456789012'

    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    it('keyId should should fail', async () => {
      async function decrypt() {
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
          //= type=test
          //# *  The "KeyId" field in the response MUST equal the configured AWS
          //# KMS key identifier.
          KeyId: 'Not the Encrypted ARN',
        }
      }
      const client: any = { decrypt }

      class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
        client,
        keyId: usEastMrkArn,
        grantTokens,
      })

      const edk1 = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: usWestMrkArn,
        encryptedDataKey: Buffer.from(usWestMrkArn),
      })

      await expect(
        testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
          edk1,
        ])
      ).to.rejectedWith(
        /KMS Decryption key does not match the requested key id./
      )
    })

    it('plaintext length should fail', async () => {
      function decrypt() {
        return {
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
          //= type=test
          //# *  The length of the response's "Plaintext" MUST equal the key
          //# derivation input length (algorithm-suites.md#key-derivation-input-
          //# length) specified by the algorithm suite (algorithm-suites.md)
          //# included in the input decryption materials
          //# (structures.md#decryption-materials).
          Plaintext: new Uint8Array(suite.keyLengthBytes - 5),
          KeyId: usEastMrkArn,
        }
      }
      const client: any = { decrypt }

      class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
        client,
        keyId: usEastMrkArn,
        grantTokens,
      })

      const edk1 = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: usEastMrkArn,
        encryptedDataKey: Buffer.from(usEastMrkArn),
      })

      await expect(
        testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
          edk1,
        ])
      ).to.eventually.rejectedWith(
        /Key length does not agree with the algorithm specification/
      )
    })
  })

  it('does not attempt to decrypt non-matching EDKs', async () => {
    const configuredKeyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const otherKeyArn =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let kmsCalled = false
    function decrypt() {
      kmsCalled = true
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        KeyId: configuredKeyId,
      }
    }
    const client: any = { decrypt }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const edk1 = new EncryptedDataKey({
      providerId: 'not aws kms edk',
      providerInfo: configuredKeyId,
      encryptedDataKey: Buffer.from(configuredKeyId),
    })

    const edk2 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: otherKeyArn,
      encryptedDataKey: Buffer.from(otherKeyArn),
    })

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId: configuredKeyId,
      grantTokens,
    })

    await expect(
      testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
        edk1,
        edk2,
      ])
    ).to.rejectedWith(Error, 'Unable to decrypt data key')
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# The set of encrypted data keys MUST first be filtered to match this
    //# keyring's configuration.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# *  Its provider ID MUST exactly match the value "aws-kms".
    expect(kmsCalled).to.equal(false)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
  //= type=test
  //# *  The the function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-
  //# for-decrypt.md#implementation) called with the configured AWS KMS
  //# key identifier and the provider info MUST return "true".
  it('does not attempt to decrypt if configured with an MRK and EDKs that do not satisfy an MRK match', async () => {
    const usEastMrkArn =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let kmsCalled = false
    function decrypt() {
      kmsCalled = true
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        KeyId: usEastMrkArn,
      }
    }
    const client: any = { decrypt }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const otherKeyArn =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const edk1 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: otherKeyArn,
      encryptedDataKey: Buffer.from(otherKeyArn),
    })

    const otherMrkArn =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-00000000-0000-0000-0000-000000000000'
    const edk2 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: otherMrkArn,
      encryptedDataKey: Buffer.from(otherMrkArn),
    })

    const otherPartitionMrkArn =
      'arn:not-aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const edk3 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: otherPartitionMrkArn,
      encryptedDataKey: Buffer.from(otherPartitionMrkArn),
    })

    const otherAccountMrkArn =
      'arn:aws:kms:us-east-1:098765432109:key/mrk-12345678123412341234123456789012'
    const edk4 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: otherAccountMrkArn,
      encryptedDataKey: Buffer.from(otherAccountMrkArn),
    })

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId: usEastMrkArn,
      grantTokens,
    })

    await expect(
      testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
        edk1,
        edk2,
        edk3,
        edk4,
      ])
    ).to.rejectedWith(Error, 'Unable to decrypt data key')
    expect(kmsCalled).to.equal(false)
  })

  it('halts and throws an error if encounters aws-kms EDK ProviderInfo with non-valid ARN', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const client: any = {}
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
      grantTokens,
    })

    const invalidKeyId = 'Not:an/ARN'
    const edk1 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: invalidKeyId,
      encryptedDataKey: Buffer.from(invalidKeyId),
    })
    await expect(
      testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [edk1])
    ).to.rejectedWith(Error, 'Malformed arn')

    const regionlessArn =
      'arn:aws:kms::2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const edk2 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: regionlessArn,
      encryptedDataKey: Buffer.from(regionlessArn),
    })
    await expect(
      testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [edk2])
    ).to.rejectedWith(Error, 'Malformed arn')

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
    //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
    //# OnDecrypt MUST fail.
    const aliasArn = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
    const edk3 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: aliasArn,
      encryptedDataKey: Buffer.from(aliasArn),
    })
    await expect(
      testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [edk3])
    ).to.rejectedWith(Error, 'Unexpected EDK ProviderInfo for AWS KMS EDK')
  })

  describe('throws an error if does not successfully decrypt any EDK', () => {
    it('because it encountered no EDKs to decrypt', async () => {
      const keyId =
        'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )

      const client: any = {}
      class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      await expect(
        new TestAwsKmsMrkAwareSymmetricKeyring({
          client,
          keyId,
          grantTokens,
        }).onDecrypt(new NodeDecryptionMaterial(suite, context), [])
      ).to.rejectedWith(Error, 'Unable to decrypt data key: No EDKs supplied.')
    })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //= type=test
    //# If this attempt
    //# results in an error, then these errors MUST be collected.
    it('and collects all errors encountered during decryption', async () => {
      const usEastMrkArn =
        'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
      const usWestMrkArn =
        'arn:aws:kms:us-west-1:123456789012:key/mrk-12345678123412341234123456789012'

      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )

      let edkCount = 0
      function decrypt() {
        edkCount += 1
        throw new Error(`Decrypt Error ${edkCount}`)
      }
      const client: any = { decrypt }

      class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
        client,
        keyId: usEastMrkArn,
        grantTokens,
      })

      const edk1 = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: usEastMrkArn,
        encryptedDataKey: Buffer.from(usEastMrkArn),
      })

      const edk2 = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: usWestMrkArn,
        encryptedDataKey: Buffer.from(usWestMrkArn),
      })
      const material = new NodeDecryptionMaterial(suite, context)

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //= type=test
      //# If the response does not satisfies these requirements then an error
      //# MUST be collected and the next encrypted data key in the filtered set
      //# MUST be attempted.
      //
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //= type=test
      //# If OnDecrypt fails to successfully decrypt any encrypted data key
      //# (structures.md#encrypted-data-key), then it MUST yield an error that
      //# includes all the collected errors.
      await expect(
        testKeyring.onDecrypt(material, [edk1, edk2])
      ).to.rejectedWith(
        Error,
        /Unable to decrypt data key[\s\S]*Decrypt Error 1[\s\S]*Decrypt Error 2/
      )
    })
  })
})
