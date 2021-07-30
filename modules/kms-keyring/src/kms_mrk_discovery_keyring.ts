// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  DecryptionMaterial,
  EncryptedDataKey,
  EncryptionMaterial,
  immutableClass,
  Keyring,
  KeyringTrace,
  KeyringTraceFlag,
  needs,
  readOnlyProperty,
  SupportedAlgorithmSuites,
  Newable,
} from '@aws-crypto/material-management'
import {
  constructArnInOtherRegion,
  isMultiRegionAwsKmsArn,
  parseAwsKmsKeyArn,
} from './arn_parsing'
import { decrypt, KMS_PROVIDER_ID } from './helpers'
import { AwsEsdkKMSInterface, RequiredDecryptResponse } from './kms_types'

export interface AwsKmsMrkAwareSymmetricDiscoveryKeyringInput<
  Client extends AwsEsdkKMSInterface
> {
  client: Client
  discoveryFilter?: Readonly<{
    accountIDs: readonly string[]
    partition: string
  }>
  grantTokens?: string[]
}

export interface IAwsKmsMrkAwareSymmetricDiscoveryKeyring<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
> extends Keyring<S> {
  client: Client
  clientRegion: string
  discoveryFilter?: Readonly<{
    accountIDs: readonly string[]
    partition: string
  }>
  grantTokens?: string[]
  _onEncrypt(material: EncryptionMaterial<S>): Promise<EncryptionMaterial<S>>
  _onDecrypt(
    material: DecryptionMaterial<S>,
    encryptedDataKeys: EncryptedDataKey[]
  ): Promise<DecryptionMaterial<S>>
}

export interface AwsKmsMrkAwareSymmetricDiscoveryKeyringConstructible<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
> {
  new (
    input: AwsKmsMrkAwareSymmetricDiscoveryKeyringInput<Client>
  ): IAwsKmsMrkAwareSymmetricDiscoveryKeyring<S, Client>
}

export function AwsKmsMrkAwareSymmetricDiscoveryKeyringClass<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
>(
  BaseKeyring: Newable<Keyring<S>>
): AwsKmsMrkAwareSymmetricDiscoveryKeyringConstructible<S, Client> {
  class AwsKmsMrkAwareSymmetricDiscoveryKeyring
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.5
    //# MUST implement that AWS Encryption SDK Keyring interface (../keyring-
    //# interface.md#interface)
    extends BaseKeyring
    implements IAwsKmsMrkAwareSymmetricDiscoveryKeyring<S, Client>
  {
    public declare client: Client
    public declare clientRegion: string
    public declare grantTokens?: string[]
    public declare discoveryFilter?: Readonly<{
      accountIDs: readonly string[]
      partition: string
    }>

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //# On initialization the caller MUST provide:
    constructor({
      client,
      grantTokens,
      discoveryFilter,
    }: AwsKmsMrkAwareSymmetricDiscoveryKeyringInput<Client>) {
      super()

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
      //# The keyring MUST know what Region the AWS KMS client is in.
      //
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
      //# It
      //# SHOULD obtain this information directly from the client as opposed to
      //# having an additional parameter.
      //
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
      //# However if it can not, then it MUST
      //# NOT create the client itself.
      //
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
      //# It SHOULD have a Region parameter and
      //# SHOULD try to identify mismatched configurations.
      //
      // @ts-ignore the V3 client has set the config to protected
      const clientRegion = client.config.region
      needs(clientRegion, 'Client must be configured to a region.')

      /* Precondition: The AwsKmsMrkAwareSymmetricDiscoveryKeyring Discovery filter *must* be able to match something.
       * I am not going to wait to tell you
       * that no CMK can match an empty account list.
       * e.g. [], [''], '' are not valid.
       */
      needs(
        !discoveryFilter ||
          (discoveryFilter.accountIDs &&
            discoveryFilter.accountIDs.length &&
            !!discoveryFilter.partition &&
            discoveryFilter.accountIDs.every(
              (a) => typeof a === 'string' && !!a
            )),
        'A discovery filter must be able to match something.'
      )

      readOnlyProperty(this, 'client', client)
      readOnlyProperty(this, 'clientRegion', clientRegion)
      readOnlyProperty(this, 'grantTokens', grantTokens)
      readOnlyProperty(
        this,
        'discoveryFilter',
        discoveryFilter
          ? Object.freeze({
              ...discoveryFilter,
              accountIDs: Object.freeze(discoveryFilter.accountIDs),
            })
          : discoveryFilter
      )
    }

    async _onEncrypt(): Promise<EncryptionMaterial<S>> {
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.7
      //# This function MUST fail.
      throw new Error(
        'AwsKmsMrkAwareSymmetricDiscoveryKeyring cannot be used to encrypt'
      )
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# OnDecrypt MUST take decryption materials (structures.md#decryption-
    //# materials) and a list of encrypted data keys
    //# (structures.md#encrypted-data-key) as input.
    async _onDecrypt(
      material: DecryptionMaterial<S>,
      encryptedDataKeys: EncryptedDataKey[]
    ): Promise<DecryptionMaterial<S>> {
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //# If the decryption materials (structures.md#decryption-materials)
      //# already contained a valid plaintext data key OnDecrypt MUST
      //# immediately return the unmodified decryption materials
      //# (structures.md#decryption-materials).
      if (material.hasValidKey()) return material

      const { client, grantTokens, clientRegion } = this

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //# The set of encrypted data keys MUST first be filtered to match this
      //# keyring's configuration.
      const decryptableEDKs = encryptedDataKeys.filter(filterEDKs(this))
      const cmkErrors: Error[] = []

      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //# For each encrypted data key in the filtered set, one at a time, the
      //# OnDecrypt MUST attempt to decrypt the data key.
      for (const edk of decryptableEDKs) {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# Otherwise it MUST
        //# be the provider info.
        let keyId = edk.providerInfo
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
        //# *  "KeyId": If the provider info's resource type is "key" and its
        //# resource is a multi-Region key then a new ARN MUST be created
        //# where the region part MUST equal the AWS KMS client region and
        //# every other part MUST equal the provider info.
        const keyArn = parseAwsKmsKeyArn(edk.providerInfo)
        needs(keyArn, 'Unexpected EDK ProviderInfo for AWS KMS EDK')
        if (isMultiRegionAwsKmsArn(keyArn)) {
          keyId = constructArnInOtherRegion(keyArn, clientRegion)
        }

        let dataKey: RequiredDecryptResponse | false = false
        try {
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
          //# When calling AWS KMS Decrypt
          //# (https://docs.aws.amazon.com/kms/latest/APIReference/
          //# API_Decrypt.html), the keyring MUST call with a request constructed
          //# as follows:
          dataKey = await decrypt(
            //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
            //# To attempt to decrypt a particular encrypted data key
            //# (structures.md#encrypted-data-key), OnDecrypt MUST call AWS KMS
            //# Decrypt (https://docs.aws.amazon.com/kms/latest/APIReference/
            //# API_Decrypt.html) with the configured AWS KMS client.
            client,
            {
              providerId: edk.providerId,
              providerInfo: keyId,
              encryptedDataKey: edk.encryptedDataKey,
            },
            material.encryptionContext,
            grantTokens
          )
          /* This should be impossible given that decrypt only returns false if the client supplier does
           * or if the providerId is not "aws-kms", which we have already filtered out
           */
          if (!dataKey) continue

          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
          //# *  The "KeyId" field in the response MUST equal the requested "KeyId"
          needs(
            dataKey.KeyId === keyId,
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

          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
          //# *  The length of the response's "Plaintext" MUST equal the key
          //# derivation input length (algorithm-suites.md#key-derivation-input-
          //# length) specified by the algorithm suite (algorithm-suites.md)
          //# included in the input decryption materials
          //# (structures.md#decryption-materials).
          //
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
          //# Since the response does satisfies these requirements then OnDecrypt
          //# MUST do the following with the response:
          //
          // setUnencryptedDataKey will throw if the plaintext does not match the algorithm suite requirements.
          material.setUnencryptedDataKey(dataKey.Plaintext, trace)
          return material
        } catch (e) {
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
          //# If the response does not satisfies these requirements then an error
          //# is collected and the next encrypted data key in the filtered set MUST
          //# be attempted.
          cmkErrors.push(e)
        }
      }
      //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
      //# If OnDecrypt fails to successfully decrypt any encrypted data key
      //# (structures.md#encrypted-data-key), then it MUST yield an error that
      //# includes all collected errors.
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
  immutableClass(AwsKmsMrkAwareSymmetricDiscoveryKeyring)
  return AwsKmsMrkAwareSymmetricDiscoveryKeyring
}

function filterEDKs<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
>({
  discoveryFilter,
  clientRegion,
}: IAwsKmsMrkAwareSymmetricDiscoveryKeyring<S, Client>) {
  return function filter({ providerId, providerInfo }: EncryptedDataKey) {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# *  Its provider ID MUST exactly match the value "aws-kms".
    if (providerId !== KMS_PROVIDER_ID) return false

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# *  The provider info MUST be a valid AWS KMS ARN (aws-kms-key-
    //# arn.md#a-valid-aws-kms-arn) with a resource type of "key" or
    //# OnDecrypt MUST fail.
    const edkArn = parseAwsKmsKeyArn(providerInfo)
    needs(
      edkArn && edkArn.ResourceType === 'key',
      'Unexpected EDK ProviderInfo for AWS KMS EDK'
    )
    const {
      AccountId: account,
      Partition: partition,
      Region: edkRegion,
    } = edkArn

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# *  If the provider info is not identified as a multi-Region key (aws-
    //# kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then the
    //# provider info's Region MUST match the AWS KMS client region.
    if (!isMultiRegionAwsKmsArn(edkArn) && clientRegion !== edkRegion) {
      return false
    }

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# *  If a discovery filter is configured, its partition and the
    //# provider info partition MUST match.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.8
    //# *  If a discovery filter is configured, its set of accounts MUST
    //# contain the provider info account.
    return (
      !discoveryFilter ||
      (discoveryFilter.partition === partition &&
        discoveryFilter.accountIDs.includes(account))
    )
  }
}
