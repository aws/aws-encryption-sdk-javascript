// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AwsKmsMrkAwareSymmetricDiscoveryKeyringClass } from '../src/kms_mrk_discovery_keyring'
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

describe('AwsKmsMrkAwareSymmetricDiscoveryKeyring: _onDecrypt', () => {
  it('returns material', async () => {
    const discoveryFilter = { accountIDs: ['2222222222222'], partition: 'aws' }
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const keyOtherRegion =
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
      expect(KeyId).to.equal(keyId)
      expect(EncryptionContext).to.deep.equal(context)
      expect(GrantTokens).to.equal(grantTokens)
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        KeyId: Buffer.from(CiphertextBlob as Uint8Array).toString('utf8'),
      }
    }
    const client: any = { decrypt, config: { region: 'us-east-1' } }
    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
      client,
      discoveryFilter,
      grantTokens,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: keyOtherRegion,
      encryptedDataKey: Buffer.from(keyId),
    })

    const otherEDK = new EncryptedDataKey({
      providerId: 'other-provider',
      providerInfo: keyId,
      encryptedDataKey: Buffer.from(keyId),
    })

    const seedMaterial = new NodeDecryptionMaterial(suite, context)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# OnDecrypt MUST take decryption materials (structures.md#decryption-
    //# materials) and a list of encrypted data keys
    //# (structures.md#encrypted-data-key) as input.
    const material = await testKeyring.onDecrypt(seedMaterial, [edk, otherEDK])

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# Since the response does satisfies these requirements then OnDecrypt
    //# MUST do the following with the response:
    expect(seedMaterial === material).to.equal(true)
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

  it('do not attempt to decrypt anything if we already a unencrypted data key.', async () => {
    const client: any = { config: { region: 'temp' } }
    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
      client,
    })

    const context = { some: 'context' }
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
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
      encryptedDataKey: new Uint8Array(1),
    })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# If the decryption materials (structures.md#decryption-materials)
    //# already contained a valid plaintext data key OnDecrypt MUST
    //# immediately return the unmodified decryption materials
    //# (structures.md#decryption-materials).
    const material = await testKeyring.onDecrypt(seedMaterial, [edk])

    expect(material === seedMaterial).to.equal(true)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
  //= type=test
  //# For each encrypted data key in the filtered set, one at a time, the
  //# OnDecrypt MUST attempt to decrypt the data key.
  it('does not halt on decrypt errors', async () => {
    const discoveryFilter = { accountIDs: ['2222222222222'], partition: 'aws' }
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const otherKeyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-0000abcd12ab34cd56ef1234567890ab'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let kmsCalls = 0
    let errorThrown = false
    async function decrypt({
      KeyId,
      // CiphertextBlob,
      EncryptionContext,
      GrantTokens,
    }: any) {
      if (kmsCalls === 0) {
        expect(KeyId).to.equal(keyId)
        kmsCalls += 1
        // This forces me to wait to throw an error
        await new Promise((resolve) => setTimeout(resolve, 10))
        errorThrown = true
        throw new Error('failed to decrypt')
      }
      // If this is not true, then we have attempted
      // the next edk before the last key was attempted.
      expect(errorThrown).to.equal(true)
      expect(kmsCalls).to.equal(1)
      expect(KeyId).to.equal(otherKeyId)
      expect(EncryptionContext).to.deep.equal(context)
      expect(GrantTokens).to.equal(grantTokens)
      kmsCalls += 1
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        KeyId: otherKeyId,
      }
    }

    const client: any = { decrypt, config: { region: 'us-east-1' } }
    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
      client,
      discoveryFilter,
      grantTokens,
    })

    const edk1 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: keyId,
      encryptedDataKey: Buffer.from(keyId),
    })

    const edk2 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: otherKeyId,
      encryptedDataKey: Buffer.from(otherKeyId),
    })

    const material = await testKeyring.onDecrypt(
      new NodeDecryptionMaterial(suite, context),
      [edk1, edk2]
    )

    expect(material.hasUnencryptedDataKey).to.equal(true)
    expect(material.keyringTrace).to.have.lengthOf(1)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
  //= type=test
  //# The set of encrypted data keys MUST first be filtered to match this
  //# keyring's configuration.
  describe('Only attemts to decrypt EDKs that match its configuration', () => {
    it('does not attempt to decrypt non-AWS KMS EDKs', async () => {
      const discoveryFilter = {
        accountIDs: ['2222222222222'],
        partition: 'aws',
      }
      const keyId =
        'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
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
          KeyId: keyId,
        }
      }
      const client: any = { decrypt, config: { region: 'us-east-1' } }
      class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
        client,
        discoveryFilter,
        grantTokens,
      })

      const edk = new EncryptedDataKey({
        providerId: 'not aws kms edk',
        providerInfo: keyId,
        encryptedDataKey: Buffer.from(keyId),
      })

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //= type=test
      //# *  Its provider ID MUST exactly match the value "aws-kms".
      await expect(
        testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
      ).to.rejectedWith(Error, 'Unable to decrypt data key')
      expect(kmsCalled).to.equal(false)
    })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
    //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
    //# OnDecrypt MUST fail.
    describe('halts and throws an error if encounters aws-kms EDK ProviderInfo with', () => {
      const client: any = { config: { region: 'us-east-1' } }
      const discoveryFilter = {
        accountIDs: ['2222222222222'],
        partition: 'aws',
      }
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )

      class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      it('a non-valid keyId', async () => {
        const keyId = 'Not:an/arn'

        const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
          client,
          discoveryFilter,
          grantTokens,
        })

        const edk = new EncryptedDataKey({
          providerId: 'aws-kms',
          providerInfo: keyId,
          encryptedDataKey: Buffer.from(keyId),
        })

        return expect(
          testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
            edk,
          ])
        ).to.rejectedWith(Error, 'Malformed arn')
      })

      it('raw key id', async () => {
        const keyId = 'mrk-80bd8ecdcd4342aebd84b7dc9da498a7'

        const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
          client,
          discoveryFilter,
          grantTokens,
        })

        const edk = new EncryptedDataKey({
          providerId: 'aws-kms',
          providerInfo: keyId,
          encryptedDataKey: Buffer.from(keyId),
        })

        return expect(
          testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
            edk,
          ])
        ).to.rejectedWith(Error, 'Unexpected EDK ProviderInfo for AWS KMS EDK')
      })

      it('a alias ARN', async () => {
        const keyId = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'

        const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
          client,
          discoveryFilter,
          grantTokens,
        })

        const edk = new EncryptedDataKey({
          providerId: 'aws-kms',
          providerInfo: keyId,
          encryptedDataKey: Buffer.from(keyId),
        })

        return expect(
          testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
            edk,
          ])
        ).to.rejectedWith(Error, 'Unexpected EDK ProviderInfo for AWS KMS EDK')
      })
    })

    describe('does not attempt to decrypt CMKs which do not match discovery filter', () => {
      const keyId =
        'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )

      // This works because both these do NOT expect to call KMS
      let kmsCalled = false
      function decrypt() {
        kmsCalled = true
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId: keyId,
        }
      }
      const client: any = { decrypt, config: { region: 'us-east-1' } }
      class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: keyId,
        encryptedDataKey: Buffer.from(keyId),
      })

      it('according to accountID', async () => {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //= type=test
        //# *  If a discovery filter is configured, its set of accounts MUST
        //# contain the provider info account.
        await expect(
          new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
            client,
            grantTokens,
            discoveryFilter: {
              accountIDs: ['Not: 2222222222222'],
              partition: 'aws',
            },
          }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
        ).to.rejectedWith(Error, 'Unable to decrypt data key')
        expect(kmsCalled).to.equal(false)
      })

      it('according to partition', async () => {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //= type=test
        //# *  If a discovery filter is configured, its partition and the
        //# provider info partition MUST match.
        await expect(
          new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
            client,
            grantTokens,
            discoveryFilter: {
              accountIDs: ['2222222222222'],
              partition: 'notAWS',
            },
          }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
        ).to.rejectedWith(Error, 'Unable to decrypt data key')
        expect(kmsCalled).to.equal(false)
      })
    })

    it('does not attempt to decrypt non-MRK CMK ARNs if it is not in our region', async () => {
      const discoveryFilter = {
        accountIDs: ['2222222222222'],
        partition: 'aws',
      }
      const keyId =
        'arn:aws:kms:us-east-2:2222222222222:key/4321abcd12ab34cd56ef1234567890ab'
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
          KeyId: keyId,
        }
      }
      const client: any = { decrypt, config: { region: 'us-east-1' } }
      class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const edk = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: keyId,
        encryptedDataKey: Buffer.from(keyId),
      })

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //= type=test
      //# *  If the provider info is not identified as a multi-Region key (aws-
      //# kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then the
      //# provider info's Region MUST match the AWS KMS client region.
      await expect(
        new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
          client,
          grantTokens,
          discoveryFilter,
        }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
      ).to.rejectedWith(Error, 'Unable to decrypt data key')
      expect(kmsCalled).to.equal(false)
    })
  })

  it('calls KMS Decrypt with keyId as an ARN indicating the configured region if an MRK-indicating ARN', async () => {
    const discoveryFilter = { accountIDs: ['2222222222222'], partition: 'aws' }
    const usWest2Key =
      'arn:aws:kms:us-west-2:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const usEast1Key =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const encryptedDataKey = Buffer.from(usEast1Key)
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# To attempt to decrypt a particular encrypted data key
    //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
    //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Decrypt.html) with the configured AWS KMS client.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //= type=test
    //# When calling AWS KMS Decrypt
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Decrypt.html), the keyring MUST call with a request constructed
    //# as follows:
    function decrypt({
      KeyId,
      EncryptionContext,
      GrantTokens,
      CiphertextBlob,
    }: any) {
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //= type=test
      //# *  "KeyId": If the provider info's resource type is "key" and its
      //# resource is a multi-Region key then a new ARN MUST be created
      //# where the region part MUST equal the AWS KMS client region and
      //# every other part MUST equal the provider info.
      expect(KeyId).to.equal(usWest2Key)
      expect(CiphertextBlob).to.deep.equal(encryptedDataKey)
      expect(EncryptionContext).to.deep.equal(context)
      expect(GrantTokens).to.equal(grantTokens)
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        KeyId,
      }
    }
    const client: any = { decrypt, config: { region: 'us-west-2' } }
    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
      client,
      discoveryFilter,
      grantTokens,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: usEast1Key,
      encryptedDataKey,
    })

    const material = await testKeyring.onDecrypt(
      new NodeDecryptionMaterial(suite, context),
      [edk]
    )

    expect(material.hasUnencryptedDataKey).to.equal(true)
  })

  it('calls KMS Decrypt with keyId as the exact ARN if not an MRK ARN', async () => {
    const discoveryFilter = { accountIDs: ['2222222222222'], partition: 'aws' }
    const keyId =
      'arn:aws:kms:us-west-2:2222222222222:key/4321abcd12ab34cd56ef1234567890ab'
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
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //= type=test
      //# Otherwise it MUST
      //# be the provider info.
      expect(KeyId).to.equal(keyId)
      expect(EncryptionContext).to.deep.equal(context)
      expect(GrantTokens).to.equal(grantTokens)
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        KeyId: Buffer.from(CiphertextBlob as Uint8Array).toString('utf8'),
      }
    }
    const client: any = { decrypt, config: { region: 'us-west-2' } }
    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
      client,
      discoveryFilter,
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
  })

  it('collects an error if the KeyId from KMS Decrypt does not match the requested KeyID.', async () => {
    const discoveryFilter = { accountIDs: ['2222222222222'], partition: 'aws' }
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    function decrypt({ KeyId, EncryptionContext }: any) {
      expect(EncryptionContext).to.deep.equal(context)
      expect(KeyId).to.equal(keyId)
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //= type=test
        //# *  The "KeyId" field in the response MUST equal the requested "KeyId"
        KeyId: 'Not the right ARN',
      }
    }
    const client: any = { decrypt, config: { region: 'us-east-1' } }
    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
      client,
      discoveryFilter,
      grantTokens,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: keyId,
      encryptedDataKey: Buffer.from(keyId),
    })

    return expect(
      testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
    ).to.rejectedWith(
      Error,
      'KMS Decryption key does not match the requested key id.'
    )
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
  //= type=test
  //# If the response does not satisfies these requirements then an error
  //# is collected and the next encrypted data key in the filtered set MUST
  //# be attempted.
  it('collects an error if the decrypted unencryptedDataKey length does not match the algorithm specification.', async () => {
    const discoveryFilter = { accountIDs: ['2222222222222'], partition: 'aws' }
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    let awsKmsCalled = 0

    function decrypt({ CiphertextBlob, EncryptionContext, GrantTokens }: any) {
      awsKmsCalled += 1
      expect(EncryptionContext).to.deep.equal(context)
      expect(GrantTokens).to.equal(grantTokens)
      return {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //= type=test
        //# *  The length of the response's "Plaintext" MUST equal the key
        //# derivation input length (algorithm-suites.md#key-derivation-input-
        //# length) specified by the algorithm suite (algorithm-suites.md)
        //# included in the input decryption materials
        //# (structures.md#decryption-materials).
        Plaintext: new Uint8Array(suite.keyLengthBytes - 5),
        KeyId: Buffer.from(CiphertextBlob as Uint8Array).toString('utf8'),
      }
    }
    const client: any = { decrypt, config: { region: 'us-east-1' } }
    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
      client,
      discoveryFilter,
      grantTokens,
    })

    const edk1 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: keyId,
      encryptedDataKey: Buffer.from(keyId),
    })

    const edk2 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: keyId,
      encryptedDataKey: Buffer.from(keyId),
    })

    await expect(
      testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
        edk1,
        edk2,
      ])
    ).to.rejectedWith(
      Error,
      'Key length does not agree with the algorithm specification.'
    )

    expect(awsKmsCalled).to.equal(2)
  })

  describe('throws an error if does not successfully decrypt any EDK', () => {
    it('because it encountered no EDKs to decrypt', async () => {
      const discoveryFilter = {
        accountIDs: ['2222222222222'],
        partition: 'aws',
      }
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )

      const client: any = { config: { region: 'us-east-1' } }
      class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
        client,
        discoveryFilter,
        grantTokens,
      })

      await expect(
        testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [])
      ).to.rejectedWith(Error, 'Unable to decrypt data key: No EDKs supplied.')
    })

    it('because it encountered decryption errors', async () => {
      const discoveryFilter = {
        accountIDs: ['2222222222222'],
        partition: 'aws',
      }
      const keyId =
        'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
      const otherKeyId =
        'arn:aws:kms:us-east-1:2222222222222:key/mrk-0000abcd12ab34cd56ef1234567890ab'
      const context = { some: 'context' }
      const grantTokens = ['grant']
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
      )

      let edkCount = 0
      function decrypt({ KeyId }: any) {
        if (edkCount === 0) {
          expect(KeyId).to.equal(keyId)
          edkCount += 1
          throw new Error('Decrypt Error 1')
        } else {
          expect(KeyId).to.equal(otherKeyId)
          edkCount += 1
          throw new Error('Decrypt Error 2')
        }
      }
      const client: any = { decrypt, config: { region: 'us-east-1' } }
      class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
        client,
        discoveryFilter,
        grantTokens,
      })

      const edk1 = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: keyId,
        encryptedDataKey: Buffer.from(keyId),
      })

      const edk2 = new EncryptedDataKey({
        providerId: 'aws-kms',
        providerInfo: otherKeyId,
        encryptedDataKey: Buffer.from(otherKeyId),
      })

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //= type=test
      //# If OnDecrypt fails to successfully decrypt any encrypted data key
      //# (structures.md#encrypted-data-key), then it MUST yield an error that
      //# includes all collected errors.
      await expect(
        testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
          edk1,
          edk2,
        ])
      ).to.rejectedWith(
        Error,
        /Unable to decrypt data key[\s\S]*Decrypt Error 1[\s\S]*Decrypt Error 2/
      )
    })
  })
})
