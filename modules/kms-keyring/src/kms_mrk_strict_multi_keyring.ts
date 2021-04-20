// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  needs,
  SupportedAlgorithmSuites,
  MultiKeyring,
  Newable,
} from '@aws-crypto/material-management'
import { IAwsKmsMrkAwareSymmetricKeyring, KmsClientSupplier } from '.'
import { AwsEsdkKMSInterface } from './kms_types'
import { getRegionFromIdentifier } from './arn_parsing'
import { awsKmsMrkAreUnique } from './aws_kms_mrk_are_unique'

export interface AwsKmsMrkAwareStrictMultiKeyringInput<
  Client extends AwsEsdkKMSInterface
> {
  clientProvider?: KmsClientSupplier<Client>
  generatorKeyId?: string
  keyIds?: string[]
  grantTokens?: string[]
}

export interface AwsKmsMrkAwareStrictMultiKeyringBuilder<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
> {
  (input: AwsKmsMrkAwareStrictMultiKeyringInput<Client>): MultiKeyring<S>
}

export function getAwsKmsMrkAwareStrictMultiKeyringBuilder<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
>(
  MrkAwareKeyring: Newable<IAwsKmsMrkAwareSymmetricKeyring<S, Client>>,
  MultiKeyring: Newable<MultiKeyring<S>>,
  defaultClientProvider: KmsClientSupplier<Client>
): AwsKmsMrkAwareStrictMultiKeyringBuilder<S, Client> {
  //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
  //# The caller MUST provide:
  return function buildAwsKmsMrkAwareStrictMultiKeyring({
    generatorKeyId,
    keyIds = [],
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# If
    //# a regional client supplier is not passed, then a default MUST be
    //# created that takes a region string and generates a default AWS SDK
    //# client for the given region.
    clientProvider = defaultClientProvider,
    grantTokens,
  }: AwsKmsMrkAwareStrictMultiKeyringInput<Client> = {}): MultiKeyring<S> {
    const identifier2Client = identifier2ClientBuilder(clientProvider)

    const allIdentifiers = generatorKeyId ? [generatorKeyId, ...keyIds] : keyIds

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# At least one non-null or non-empty string AWS
    //# KMS key identifiers exists in the input this function MUST fail.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# If any of the AWS KMS key identifiers is null or an empty string this
    //# function MUST fail.
    needs(
      allIdentifiers.length &&
        allIdentifiers.every((key) => typeof key === 'string' && key !== ''),
      'Noop keyring is not allowed: Set a generatorKeyId or at least one keyId.'
    )

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# All
    //# AWS KMS identifiers are passed to Assert AWS KMS MRK are unique (aws-
    //# kms-mrk-are-unique.md#Implementation) and the function MUST return
    //# success otherwise this MUST fail.
    awsKmsMrkAreUnique(allIdentifiers)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# If there is a generator input then the generator keyring MUST be a
    //# AWS KMS MRK Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-
    //# keyring.md) initialized with
    const generator = generatorKeyId
      ? new MrkAwareKeyring({
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
          //# *  The AWS KMS client that MUST be created by the regional client
          //# supplier when called with the region part of the generator ARN or
          //# a signal for the AWS SDK to select the default region.
          client: identifier2Client(generatorKeyId),
          keyId: generatorKeyId,
          grantTokens,
        })
      : undefined

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# If there is a set of child identifiers then a set of AWS KMS MRK
    //# Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-keyring.md) MUST
    //# be created for each AWS KMS key identifier by initialized each
    //# keyring with
    const children: IAwsKmsMrkAwareSymmetricKeyring<S, Client>[] = keyIds.map(
      (keyId) => {
        return new MrkAwareKeyring({
          //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
          //# *  The AWS KMS client that MUST be created by the regional client
          //# supplier when called with the region part of the AWS KMS key
          //# identifier or a signal for the AWS SDK to select the default
          //# region.
          client: identifier2Client(keyId),
          keyId,
          grantTokens,
        })
      }
    )

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
    //# by using this generator keyring as the generator keyring (../multi-
    //# keyring.md#generator-keyring) and this set of child keyrings as the
    //# child keyrings (../multi-keyring.md#child-keyrings).
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# This Multi-
    //# Keyring MUST be this functions output.
    return new MultiKeyring({
      generator,
      children,
    })
  }
}

export function identifier2ClientBuilder<Client extends AwsEsdkKMSInterface>(
  clientProvider: KmsClientSupplier<Client>
): (identifier: string) => Client {
  return function identifier2Client(identifier: string): Client {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //# NOTE: The AWS Encryption SDK SHOULD NOT attempt to evaluate its own
    //# default region.
    const region = getRegionFromIdentifier(identifier)
    const client = clientProvider(region)
    /* Postcondition: If the configured clientProvider is not able to create a client for a defined generator key, throw an error. */
    needs(
      client,
      `Configured clientProvider is unable to create a client for configured ${identifier}.`
    )
    return client
  }
}
