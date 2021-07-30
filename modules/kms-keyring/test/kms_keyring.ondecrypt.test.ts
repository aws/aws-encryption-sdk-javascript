// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { KmsKeyringClass } from '../src/kms_keyring'
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

describe('KmsKeyring: _onDecrypt', () => {
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
      return { decrypt }
      function decrypt({
        KeyId,
        CiphertextBlob,
        EncryptionContext,
        GrantTokens,
      }: any) {
        expect(KeyId).to.equal(generatorKeyId)
        expect(EncryptionContext).to.deep.equal(context)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId: Buffer.from(CiphertextBlob as Uint8Array).toString('utf8'),
        }
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
      keyIds,
      grantTokens,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
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
    expect(
      traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
    expect(
      traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX)
  })

  it('Check for early return (Postcondition): There is no discoveryFilter to further condition discovery.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const discovery = true
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return { decrypt }
      function decrypt({
        KeyId,
        CiphertextBlob,
        EncryptionContext,
        GrantTokens,
      }: any) {
        expect(KeyId).to.equal(generatorKeyId)
        expect(EncryptionContext).to.deep.equal(context)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId: Buffer.from(CiphertextBlob as Uint8Array).toString('utf8'),
        }
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      grantTokens,
      discovery,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
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
    expect(
      traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY)
    expect(
      traceDecrypt.flags & KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX
    ).to.equal(KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX)
  })

  it('Postcondition: Provider info is a well formed AWS KMS ARN.', async () => {
    const aliasArn = 'alias/example-alias'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const discovery = true
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let kmsCalled = false
    const clientProvider: any = () => {
      kmsCalled = true
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: aliasArn,
      encryptedDataKey: Buffer.from(aliasArn),
    })

    await expect(
      new TestKmsKeyring({
        clientProvider,
        grantTokens,
        discovery,
        discoveryFilter: { partition: 'aws', accountIDs: ['123456789012'] },
      }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
    ).to.eventually.rejectedWith('Malformed arn in provider info.')
    expect(kmsCalled).to.equal(false)
  })

  it('decrypt errors should not halt', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const keyName =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'

    const context = { some: 'context' }
    const grantTokens = ['grant']
    const discovery = true
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let edkCount = 0
    const clientProvider: any = () => {
      return { decrypt }
      function decrypt({
        KeyId,
        // CiphertextBlob,
        EncryptionContext,
        GrantTokens,
      }: any) {
        if (edkCount === 0) {
          expect(KeyId).to.equal(generatorKeyId)
          edkCount += 1
          throw new Error('failed to decrypt')
        }
        expect(KeyId).to.equal(keyName)
        expect(EncryptionContext).to.deep.equal(context)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId: keyName,
        }
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      grantTokens,
      discovery,
    })

    const edk1 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
    })

    const edk2 = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: keyName,
      encryptedDataKey: Buffer.from(generatorKeyId),
    })

    const material = await testKeyring.onDecrypt(
      new NodeDecryptionMaterial(suite, context),
      [edk1, edk2]
    )

    expect(material.hasUnencryptedDataKey).to.equal(true)
    expect(material.keyringTrace).to.have.lengthOf(1)
  })

  it('Check for early return (Postcondition): Only AWS KMS EDK should be attempted.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const discovery = true
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let kmsCalled = false
    const clientProvider: any = () => {
      kmsCalled = true
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const edk = new EncryptedDataKey({
      providerId: 'not aws kms edk',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
    })

    const materialNotAccount = await new TestKmsKeyring({
      clientProvider,
      grantTokens,
      discovery,
    }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
    expect(materialNotAccount.hasUnencryptedDataKey).to.equal(false)

    expect(kmsCalled).to.equal(false)
  })

  it('Postcondition: The account and partition *must* match the discovery filter.', async () => {
    const encryptKmsKey =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const discovery = true
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let kmsCalled = false
    const clientProvider: any = () => {
      kmsCalled = true
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: encryptKmsKey,
      encryptedDataKey: Buffer.from(encryptKmsKey),
    })

    const materialNotAccount = await new TestKmsKeyring({
      clientProvider,
      grantTokens,
      discovery,
      discoveryFilter: { accountIDs: ['Not: 123456789012'], partition: 'aws' },
    }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
    expect(materialNotAccount.hasUnencryptedDataKey).to.equal(false)

    const materialNotPartition = await new TestKmsKeyring({
      clientProvider,
      grantTokens,
      discovery,
      discoveryFilter: { accountIDs: ['123456789012'], partition: 'notAWS' },
    }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
    expect(materialNotPartition.hasUnencryptedDataKey).to.equal(false)

    const materialNotBoth = await new TestKmsKeyring({
      clientProvider,
      grantTokens,
      discovery,
      discoveryFilter: {
        accountIDs: ['Not: 123456789012'],
        partition: 'notAWS',
      },
    }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
    expect(materialNotBoth.hasUnencryptedDataKey).to.equal(false)

    expect(kmsCalled).to.equal(false)
  })

  it('Check for early return (Postcondition): clientProvider may not return a client.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const encryptKmsKey =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const keyIds = [encryptKmsKey]
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => false
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
      keyIds,
      grantTokens,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
    })

    const material = await testKeyring.onDecrypt(
      new NodeDecryptionMaterial(suite, encryptionContext),
      [edk]
    )

    expect(material.hasUnencryptedDataKey).to.equal(false)
    expect(material.keyringTrace).to.have.lengthOf(0)
  })

  it('Postcondition: The KeyId from KMS must match the encoded KeyID.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const encryptKmsKey =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const keyIds = [encryptKmsKey]
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return { decrypt }
      function decrypt({ EncryptionContext, GrantTokens }: any) {
        expect(EncryptionContext).to.deep.equal(encryptionContext)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes),
          KeyId: 'Not the Encrypted ARN',
        }
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
      keyIds,
      grantTokens,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
    })

    return expect(
      testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, encryptionContext),
        [edk]
      )
    ).to.rejectedWith(
      Error,
      'KMS Decryption key does not match the requested key id.'
    )
  })

  it('Postcondition: The decrypted unencryptedDataKey length must match the algorithm specification.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const encryptKmsKey =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const keyIds = [encryptKmsKey]
    const encryptionContext = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProvider: any = () => {
      return { decrypt }
      function decrypt({
        CiphertextBlob,
        EncryptionContext,
        GrantTokens,
      }: any) {
        expect(EncryptionContext).to.deep.equal(encryptionContext)
        expect(GrantTokens).to.equal(grantTokens)
        return {
          Plaintext: new Uint8Array(suite.keyLengthBytes - 5),
          KeyId: Buffer.from(CiphertextBlob as Uint8Array).toString('utf8'),
        }
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
      keyIds,
      grantTokens,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
    })

    return expect(
      testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, encryptionContext),
        [edk]
      )
    ).to.rejectedWith(
      Error,
      'Key length does not agree with the algorithm specification.'
    )
  })

  it('Postcondition: A CMK must provide a valid data key or KMS must not have raised any errors.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const discovery = true
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    const clientProviderError: any = () => {
      return { decrypt }
      function decrypt() {
        throw new Error('failed to decrypt')
      }
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsKeyring({
      clientProvider: clientProviderError,
      grantTokens,
      discovery,
    })

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
    })

    await expect(
      testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), [
        edk,
        edk,
      ])
    ).to.rejectedWith(
      Error,
      'Unable to decrypt data key and one or more KMS CMKs had an error.'
    )

    /* This will make the decrypt loop not have an error.
     * This will exercise the `(!material.hasValidKey() && !cmkErrors.length)` `needs` condition.
     */
    const clientProviderNoError: any = () => false
    await expect(
      new TestKmsKeyring({
        clientProvider: clientProviderNoError,
        grantTokens,
        discovery,
      }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk, edk])
    ).to.not.rejectedWith(Error)
  })

  it('Postcondition: The EDK CMK (providerInfo) *must* match a configured CMK.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const context = { some: 'context' }
    const grantTokens = ['grant']
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )

    let kmsCalled = false
    const clientProvider: any = () => {
      kmsCalled = true
    }
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const edk = new EncryptedDataKey({
      providerId: 'aws-kms',
      providerInfo: generatorKeyId,
      encryptedDataKey: Buffer.from(generatorKeyId),
    })

    const materialNotAccount = await new TestKmsKeyring({
      clientProvider,
      grantTokens,
      keyIds: ['arn:aws:kms:us-east-1:123456789012:alias/NOT-example-alias'],
    }).onDecrypt(new NodeDecryptionMaterial(suite, context), [edk])
    expect(materialNotAccount.hasUnencryptedDataKey).to.equal(false)

    expect(kmsCalled).to.equal(false)
  })
})
