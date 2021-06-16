// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AwsKmsMrkAwareSymmetricKeyringClass } from '../src/kms_mrk_keyring'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  NodeEncryptionMaterial,
  KeyringTraceFlag,
  Keyring,
  Newable,
} from '@aws-crypto/material-management'
chai.use(chaiAsPromised)
const { expect } = chai

describe('AwsKmsMrkAwareSymmetricKeyring: _onEncrypt', () => {
  it('Updates materials with data from KMS GenerateDataKey if input materials do not contain plaintext data key', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    let generateCalled = false

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the input encryption materials (structures.md#encryption-
    //# materials) do not contain a plaintext data key OnEncrypt MUST attempt
    //# to generate a new plaintext data key by calling AWS KMS
    //# GenerateDataKey (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_GenerateDataKey.html).
    function generateDataKey({
      KeyId,
      EncryptionContext,
      GrantTokens,
      NumberOfBytes,
    }: any) {
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
      //= type=test
      //# The keyring MUST call
      //# AWS KMS GenerateDataKeys with a request constructed as follows:
      expect(EncryptionContext).to.deep.equal(context)
      expect(GrantTokens).to.equal(grantTokens)
      expect(KeyId).to.equal(KeyId)
      expect(NumberOfBytes).to.equal(suite.keyLengthBytes)
      generateCalled = true
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        KeyId,
        CiphertextBlob: new Uint8Array(5),
      }
    }

    const client: any = { generateDataKey }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
      grantTokens,
    })

    const seedMaterial = new NodeEncryptionMaterial(suite, context)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# OnEncrypt MUST take encryption materials (structures.md#encryption-
    //# materials) as input.
    const material = await testKeyring.onEncrypt(seedMaterial)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If verified,
    //# OnEncrypt MUST do the following with the response from AWS KMS
    //# GenerateDataKey (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_GenerateDataKey.html):
    expect(material.hasUnencryptedDataKey).to.equal(true)

    expect(material.encryptedDataKeys).to.have.lengthOf(1)
    const [edkGenerate] = material.encryptedDataKeys
    expect(edkGenerate.providerId).to.equal('aws-kms')
    expect(edkGenerate.providerInfo).to.equal(keyId)

    expect(material.keyringTrace).to.have.lengthOf(2)
    const [traceGenerate, traceEncrypt1] = material.keyringTrace
    expect(traceGenerate.keyNamespace).to.equal('aws-kms')
    expect(traceGenerate.keyName).to.equal(keyId)
    expect(
      traceGenerate.flags & KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY)
    expect(
      traceGenerate.flags & KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    expect(
      traceGenerate.flags & KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX)

    expect(traceEncrypt1.keyNamespace).to.equal('aws-kms')
    expect(traceEncrypt1.keyName).to.equal(keyId)
    expect(
      traceEncrypt1.flags & KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    expect(
      traceEncrypt1.flags & KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# *  OnEncrypt MUST output the modified encryption materials
    //# (structures.md#encryption-materials)
    expect(seedMaterial === material).to.equal(true)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the
    //# configured AWS KMS client to make the call.
    expect(generateCalled).to.equal(true)
  })

  it('The generated unencryptedDataKey length must match the algorithm specification.', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    function generateDataKey({ KeyId, EncryptionContext, GrantTokens }: any) {
      expect(EncryptionContext).to.deep.equal(encryptionContext)
      expect(GrantTokens).to.equal(grantTokens)
      return {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //= type=test
        //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that
        //# the response "Plaintext" length matches the specification of the
        //# algorithm suite (algorithm-suites.md)'s Key Derivation Input Length
        //# field.
        Plaintext: new Uint8Array(suite.keyLengthBytes - 5),
        KeyId,
        CiphertextBlob: new Uint8Array(5),
      }
    }
    const client: any = { generateDataKey }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
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

  it('The KeyID returned by KMS GenerateDataKey must be a valid ARN', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    function generateDataKey({ EncryptionContext, GrantTokens }: any) {
      expect(EncryptionContext).to.deep.equal(encryptionContext)
      expect(GrantTokens).to.equal(grantTokens)
      return {
        Plaintext: new Uint8Array(suite.keyLengthBytes),
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //= type=test
        //# The Generate Data Key response's "KeyId" MUST be A valid AWS
        //# KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-
        //# key).
        KeyId: 'Not an arn',
        CiphertextBlob: new Uint8Array(5),
      }
    }
    const client: any = { generateDataKey }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
      grantTokens,
    })

    return await expect(
      testKeyring.onEncrypt(
        new NodeEncryptionMaterial(suite, encryptionContext)
      )
    ).to.rejectedWith(Error, 'Malformed arn')
  })

  it('fails if KMS GenerateDataKey fails', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    function generateDataKey() {
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
      //= type=test
      //# If the call to AWS KMS GenerateDataKey
      //# (https://docs.aws.amazon.com/kms/latest/APIReference/
      //# API_GenerateDataKey.html) does not succeed, OnEncrypt MUST NOT modify
      //# the encryption materials (structures.md#encryption-materials) and
      //# MUST fail.
      throw new Error('failed to generate data key')
    }
    const client: any = { generateDataKey }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
      grantTokens,
    })

    const material = new NodeEncryptionMaterial(suite, encryptionContext)

    await expect(testKeyring.onEncrypt(material)).to.rejectedWith(
      Error,
      'failed to generate data key'
    )
    expect(material.hasValidKey()).to.equal(false)
    expect(material.encryptedDataKeys.length).to.equal(0)
  })

  it('Updates materials with data from KMS Encrypt if input materials contain plaintext data key.', async () => {
    const configuredKeyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    const udk = new Uint8Array(suite.keyLengthBytes).fill(2)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# The keyring MUST call AWS KMS Encrypt
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Encrypt.html) using the configured AWS KMS client.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# The keyring
    //# MUST AWS KMS Encrypt call with a request constructed as follows:
    function encrypt({
      KeyId,
      EncryptionContext,
      GrantTokens,
      Plaintext,
    }: any) {
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
      //= type=test
      //# Given a plaintext data key in the encryption materials
      //# (structures.md#encryption-materials), OnEncrypt MUST attempt to
      //# encrypt the plaintext data key using the configured AWS KMS key
      //# identifier.
      expect(KeyId).to.equal(configuredKeyId)
      expect(Plaintext).to.deep.equal(udk)
      expect(EncryptionContext).to.deep.equal(encryptionContext)
      expect(GrantTokens).to.equal(grantTokens)
      return {
        KeyId,
        CiphertextBlob: new Uint8Array(5),
        grantTokens,
      }
    }
    const client: any = { encrypt }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId: configuredKeyId,
      grantTokens,
    })

    const seedMaterial = new NodeEncryptionMaterial(
      suite,
      encryptionContext
    ).setUnencryptedDataKey(new Uint8Array(udk), {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })

    const material = await testKeyring.onEncrypt(seedMaterial)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If verified, OnEncrypt MUST do the following with the response from
    //# AWS KMS Encrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Encrypt.html):
    expect(material.encryptedDataKeys).to.have.lengthOf(1)
    const [kmsEDK] = material.encryptedDataKeys
    expect(kmsEDK.providerId).to.equal('aws-kms')
    expect(kmsEDK.providerInfo).to.equal(configuredKeyId)

    expect(material.keyringTrace).to.have.lengthOf(2)
    const [, kmsTrace] = material.keyringTrace
    expect(kmsTrace.keyNamespace).to.equal('aws-kms')
    expect(kmsTrace.keyName).to.equal(configuredKeyId)
    expect(
      kmsTrace.flags & KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY)
    expect(
      kmsTrace.flags & KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If all Encrypt calls succeed, OnEncrypt MUST output the modified
    //# encryption materials (structures.md#encryption-materials).
    expect(material === seedMaterial).to.equal(true)
  })

  it('The KeyID returned by KMS Encrypt must be a valid ARN', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    function encrypt({ EncryptionContext, GrantTokens }: any) {
      expect(EncryptionContext).to.deep.equal(encryptionContext)
      expect(GrantTokens).to.equal(grantTokens)
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
      //= type=test
      //# If the Encrypt call succeeds The response's "KeyId" MUST be A valid
      //# AWS KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-
      //# region-key).
      return {
        KeyId: 'Not an arn',
        CiphertextBlob: new Uint8Array(5),
        grantTokens,
      }
    }
    const client: any = { encrypt }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
      grantTokens,
    })

    const seedMaterial = new NodeEncryptionMaterial(
      suite,
      encryptionContext
    ).setUnencryptedDataKey(new Uint8Array(suite.keyLengthBytes), {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })

    return expect(testKeyring.onEncrypt(seedMaterial)).to.rejectedWith(
      Error,
      'Malformed arn'
    )
  })

  it('fails if KMS Encrypt fails', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    function encrypt() {
      throw new Error('failed to encrypt')
    }
    const client: any = { encrypt }
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
      grantTokens,
    })

    const seedMaterial = new NodeEncryptionMaterial(
      suite,
      encryptionContext
    ).setUnencryptedDataKey(new Uint8Array(suite.keyLengthBytes), {
      keyName: 'keyName',
      keyNamespace: 'keyNamespace',
      flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
    })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //= type=test
    //# If the call to AWS KMS Encrypt
    //# (https://docs.aws.amazon.com/kms/latest/APIReference/
    //# API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
    await expect(testKeyring.onEncrypt(seedMaterial)).to.rejectedWith(
      Error,
      'failed to encrypt'
    )
    expect(seedMaterial.encryptedDataKeys.length).to.equal(0)
  })
})
