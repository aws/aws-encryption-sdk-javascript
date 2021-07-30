// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AwsEsdkKMSInterface } from './kms_types'
import {
  needs,
  Keyring,
  EncryptionMaterial,
  DecryptionMaterial,
  SupportedAlgorithmSuites,
  KeyringTrace,
  KeyringTraceFlag,
  EncryptedDataKey,
  immutableClass,
  readOnlyProperty,
  unwrapDataKey,
  Newable,
} from '@aws-crypto/material-management'
import {
  KMS_PROVIDER_ID,
  generateDataKey,
  encrypt,
  decrypt,
  kmsResponseToEncryptedDataKey,
} from './helpers'
import {
  mrkAwareAwsKmsKeyIdCompare,
  parseAwsKmsKeyArn,
  validAwsKmsIdentifier,
} from './arn_parsing'

export interface AwsKmsMrkAwareSymmetricKeyringInput<
  Client extends AwsEsdkKMSInterface
> {
  keyId: string
  client: Client
  grantTokens?: string[]
}

export interface IAwsKmsMrkAwareSymmetricKeyring<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
> extends Keyring<S> {
  keyId: string
  client: Client
  grantTokens?: string[]
  _onEncrypt(material: EncryptionMaterial<S>): Promise<EncryptionMaterial<S>>
  _onDecrypt(
    material: DecryptionMaterial<S>,
    encryptedDataKeys: EncryptedDataKey[]
  ): Promise<DecryptionMaterial<S>>
}

export interface AwsKmsMrkAwareSymmetricKeyringConstructible<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
> {
  new (
    input: AwsKmsMrkAwareSymmetricKeyringInput<Client>
  ): IAwsKmsMrkAwareSymmetricKeyring<S, Client>
}

export function AwsKmsMrkAwareSymmetricKeyringClass<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
>(
  BaseKeyring: Newable<Keyring<S>>
): AwsKmsMrkAwareSymmetricKeyringConstructible<S, Client> {
  class AwsKmsMrkAwareSymmetricKeyring
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.5
    //# MUST implement the AWS Encryption SDK Keyring interface (../keyring-
    //# interface.md#interface)
    extends BaseKeyring
    implements IAwsKmsMrkAwareSymmetricKeyring<S, Client>
  {
    public keyId!: string
    public client!: Client
    public grantTokens?: string[]

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //# On initialization the caller MUST provide:
    constructor({
      client,
      keyId,
      grantTokens,
    }: AwsKmsMrkAwareSymmetricKeyringInput<Client>) {
      super()

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
      //# The AWS KMS key identifier MUST NOT be null or empty.
      needs(
        keyId && typeof keyId === 'string',
        'An AWS KMS key identifier is required.'
      )

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
      //# The AWS KMS
      //# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
      //# valid-aws-kms-identifier).
      needs(
        validAwsKmsIdentifier(keyId),
        `Key id ${keyId} is not a valid identifier.`
      )

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
      //# The AWS KMS
      //# SDK client MUST NOT be null.
      needs(!!client, 'An AWS SDK client is required')

      readOnlyProperty(this, 'client', client)
      readOnlyProperty(this, 'keyId', keyId)
      readOnlyProperty(this, 'grantTokens', grantTokens)
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
    //# OnEncrypt MUST take encryption materials (structures.md#encryption-
    //# materials) as input.
    async _onEncrypt(
      material: EncryptionMaterial<S>
    ): Promise<EncryptionMaterial<S>> {
      const { client, keyId, grantTokens } = this
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
      //# If the input encryption materials (structures.md#encryption-
      //# materials) do not contain a plaintext data key OnEncrypt MUST attempt
      //# to generate a new plaintext data key by calling AWS KMS
      //# GenerateDataKey (https://docs.aws.amazon.com/kms/latest/APIReference/
      //# API_GenerateDataKey.html).
      if (!material.hasUnencryptedDataKey) {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# The keyring MUST call
        //# AWS KMS GenerateDataKeys with a request constructed as follows:
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If the call to AWS KMS GenerateDataKey
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_GenerateDataKey.html) does not succeed, OnEncrypt MUST NOT modify
        //# the encryption materials (structures.md#encryption-materials) and
        //# MUST fail.
        const dataKey = await generateDataKey(
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
          //# If the keyring calls AWS KMS GenerateDataKeys, it MUST use the
          //# configured AWS KMS client to make the call.
          client,
          material.suite.keyLengthBytes,
          keyId,
          material.encryptionContext,
          grantTokens
        )
        /* This should be impossible given that generateDataKey only returns false if the client supplier does. */
        needs(dataKey, 'Generator KMS key did not generate a data key')

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# The Generate Data Key response's "KeyId" MUST be A valid AWS
        //# KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-
        //# key).
        needs(parseAwsKmsKeyArn(dataKey.KeyId), 'Malformed arn.')

        const flags =
          KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY |
          KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX |
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
        const trace: KeyringTrace = {
          keyNamespace: KMS_PROVIDER_ID,
          keyName: dataKey.KeyId,
          flags,
        }

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If verified,
        //# OnEncrypt MUST do the following with the response from AWS KMS
        //# GenerateDataKey (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_GenerateDataKey.html):
        material
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
          //# If the Generate Data Key call succeeds, OnEncrypt MUST verify that
          //# the response "Plaintext" length matches the specification of the
          //# algorithm suite (algorithm-suites.md)'s Key Derivation Input Length
          //# field.
          //
          // setUnencryptedDataKey will throw if the plaintext does not match the algorithm suite requirements.
          .setUnencryptedDataKey(dataKey.Plaintext, trace)
          .addEncryptedDataKey(
            kmsResponseToEncryptedDataKey(dataKey),
            KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY |
              KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX
          )

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# *  OnEncrypt MUST output the modified encryption materials
        //# (structures.md#encryption-materials)
        return material
      } else {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# Given a plaintext data key in the encryption materials
        //# (structures.md#encryption-materials), OnEncrypt MUST attempt to
        //# encrypt the plaintext data key using the configured AWS KMS key
        //# identifier.

        const unencryptedDataKey = unwrapDataKey(
          material.getUnencryptedDataKey()
        )

        const flags =
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY |
          KeyringTraceFlag.WRAPPING_KEY_SIGNED_ENC_CTX

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If the call to AWS KMS Encrypt
        //# (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Encrypt.html) does not succeed, OnEncrypt MUST fail.
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# The keyring
        //# MUST AWS KMS Encrypt call with a request constructed as follows:
        const kmsEDK = await encrypt(
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
          //# The keyring MUST call AWS KMS Encrypt
          //# (https://docs.aws.amazon.com/kms/latest/APIReference/
          //# API_Encrypt.html) using the configured AWS KMS client.
          client,
          unencryptedDataKey,
          keyId,
          material.encryptionContext,
          grantTokens
        )

        /* This should be impossible given that encrypt only returns false if the client supplier does. */
        needs(
          kmsEDK,
          'AwsKmsMrkAwareSymmetricKeyring failed to encrypt data key'
        )

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If the Encrypt call succeeds The response's "KeyId" MUST be A valid
        //# AWS KMS key ARN (aws-kms-key-arn.md#identifying-an-aws-kms-multi-
        //# region-key).
        needs(parseAwsKmsKeyArn(kmsEDK.KeyId), 'Malformed arn.')

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If verified, OnEncrypt MUST do the following with the response from
        //# AWS KMS Encrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
        //# API_Encrypt.html):
        material.addEncryptedDataKey(
          kmsResponseToEncryptedDataKey(kmsEDK),
          flags
        )

        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.7
        //# If all Encrypt calls succeed, OnEncrypt MUST output the modified
        //# encryption materials (structures.md#encryption-materials).
        return material
      }
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# OnDecrypt MUST take decryption materials (structures.md#decryption-
    //# materials) and a list of encrypted data keys
    //# (structures.md#encrypted-data-key) as input.
    async _onDecrypt(
      material: DecryptionMaterial<S>,
      encryptedDataKeys: EncryptedDataKey[]
    ): Promise<DecryptionMaterial<S>> {
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //# If the decryption materials (structures.md#decryption-materials)
      //# already contained a valid plaintext data key OnDecrypt MUST
      //# immediately return the unmodified decryption materials
      //# (structures.md#decryption-materials).
      if (material.hasValidKey()) return material

      const { client, keyId, grantTokens } = this

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //# The set of encrypted data keys MUST first be filtered to match this
      //# keyring's configuration.
      const decryptableEDKs = encryptedDataKeys.filter(filterEDKs(keyId))

      const cmkErrors: Error[] = []

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //# For each encrypted data key in the filtered set, one at a time, the
      //# OnDecrypt MUST attempt to decrypt the data key.
      for (const edk of decryptableEDKs) {
        const { providerId, encryptedDataKey } = edk
        try {
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
          //# When calling AWS KMS Decrypt
          //# (https://docs.aws.amazon.com/kms/latest/APIReference/
          //# API_Decrypt.html), the keyring MUST call with a request constructed
          //# as follows:
          const dataKey = await decrypt(
            //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
            //# To attempt to decrypt a particular encrypted data key
            //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
            //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
            //# API_Decrypt.html) with the configured AWS KMS client.
            client,
            // For MRKs the key identifier MUST be the configured key identifer.
            { providerId, encryptedDataKey, providerInfo: this.keyId },
            material.encryptionContext,
            grantTokens
          )
          /* This should be impossible given that decrypt only returns false if the client supplier does
           * or if the providerId is not "aws-kms", which we have already filtered out
           */
          needs(dataKey, 'decrypt did not return a data key.')

          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
          //# *  The "KeyId" field in the response MUST equal the configured AWS
          //# KMS key identifier.
          needs(
            dataKey.KeyId === this.keyId,
            'KMS Decryption key does not match the requested key id.'
          )

          const flags =
            KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY |
            KeyringTraceFlag.WRAPPING_KEY_VERIFIED_ENC_CTX
          const trace: KeyringTrace = {
            keyNamespace: KMS_PROVIDER_ID,
            keyName: dataKey.KeyId,
            flags,
          }

          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
          //# If the response does satisfies these requirements then OnDecrypt MUST
          //# do the following with the response:
          //
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
          //# *  The length of the response's "Plaintext" MUST equal the key
          //# derivation input length (algorithm-suites.md#key-derivation-input-
          //# length) specified by the algorithm suite (algorithm-suites.md)
          //# included in the input decryption materials
          //# (structures.md#decryption-materials).
          //
          // setUnencryptedDataKey will throw if the plaintext does not match the algorithm suite requirements.
          material.setUnencryptedDataKey(dataKey.Plaintext, trace)
          return material
        } catch (e) {
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
          //# If this attempt
          //# results in an error, then these errors MUST be collected.
          //
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
          //# If the response does not satisfies these requirements then an error
          //# MUST be collected and the next encrypted data key in the filtered set
          //# MUST be attempted.
          cmkErrors.push(e)
        }
      }

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
      //# If OnDecrypt fails to successfully decrypt any encrypted data key
      //# (structures.md#encrypted-data-key), then it MUST yield an error that
      //# includes all the collected errors.
      needs(
        material.hasValidKey(),
        [
          `Unable to decrypt data key${
            !decryptableEDKs.length ? ': No EDKs supplied' : ''
          }.`,
          ...cmkErrors.map((e, i) => `Error #${i + 1}  \n${e.stack}`),
        ].join('\n')
      )

      return material
    }
  }
  immutableClass(AwsKmsMrkAwareSymmetricKeyring)
  return AwsKmsMrkAwareSymmetricKeyring
}

function filterEDKs(keyringKeyId: string) {
  return function filter({ providerId, providerInfo }: EncryptedDataKey) {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# *  Its provider ID MUST exactly match the value "aws-kms".
    if (providerId !== KMS_PROVIDER_ID) return false

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
    //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
    //# OnDecrypt MUST fail.
    const arnInfo = parseAwsKmsKeyArn(providerInfo)
    needs(
      arnInfo && arnInfo.ResourceType === 'key',
      'Unexpected EDK ProviderInfo for AWS KMS EDK'
    )

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.8
    //# *  The the function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-
    //# for-decrypt.md#implementation) called with the configured AWS KMS
    //# key identifier and the provider info MUST return "true".
    return mrkAwareAwsKmsKeyIdCompare(keyringKeyId, providerInfo)
  }
}
