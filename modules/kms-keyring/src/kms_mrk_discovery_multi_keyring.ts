// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  needs,
  SupportedAlgorithmSuites,
  MultiKeyring,
  Newable,
} from '@aws-crypto/material-management'
import { IAwsKmsMrkAwareSymmetricDiscoveryKeyring, KmsClientSupplier } from '.'
import { AwsEsdkKMSInterface } from './kms_types'

export interface AwsKmsMrkAwareDiscoveryMultiKeyringInput<
  Client extends AwsEsdkKMSInterface
> {
  regions: string[]
  clientProvider?: KmsClientSupplier<Client>
  discoveryFilter?: Readonly<{
    accountIDs: readonly string[]
    partition: string
  }>
  grantTokens?: string[]
}

export interface AwsKmsMrkAwareDiscoveryMultiKeyringBuilder<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
> {
  (input: AwsKmsMrkAwareDiscoveryMultiKeyringInput<Client>): MultiKeyring<S>
}

export function getAwsKmsMrkAwareDiscoveryMultiKeyringBuilder<
  S extends SupportedAlgorithmSuites,
  Client extends AwsEsdkKMSInterface
>(
  MrkAwareDiscoveryKeyring: Newable<
    IAwsKmsMrkAwareSymmetricDiscoveryKeyring<S, Client>
  >,
  MultiKeyring: Newable<MultiKeyring<S>>,
  defaultClientProvider: KmsClientSupplier<Client>
): AwsKmsMrkAwareDiscoveryMultiKeyringBuilder<S, Client> {
  //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
  //# The caller MUST provide:
  return function buildAwsKmsMrkAwareDiscoveryMultiKeyringNode({
    regions,
    discoveryFilter,
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# If a regional client supplier is not passed,
    //# then a default MUST be created that takes a region string and
    //# generates a default AWS SDK client for the given region.
    clientProvider = defaultClientProvider,
    grantTokens,
  }: AwsKmsMrkAwareDiscoveryMultiKeyringInput<Client>): MultiKeyring<S> {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# If an empty set of Region is provided this function MUST fail.
    needs(
      regions.length,
      'Configured regions must contain at least one region.'
    )

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# If
    //# any element of the set of regions is null or an empty string this
    //# function MUST fail.
    needs(
      regions.every((region) => typeof region === 'string' && !!region),
      'Configured regions must not contain a null or empty string as a region.'
    )

    const children: IAwsKmsMrkAwareSymmetricDiscoveryKeyring<S, Client>[] =
      regions
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
        //# A set of AWS KMS clients MUST be created by calling regional client
        //# supplier for each region in the input set of regions.
        .map(clientProvider)
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
        //# Then a set of AWS KMS MRK Aware Symmetric Region Discovery Keyring
        //# (aws-kms-mrk-aware-symmetric-region-discovery-keyring.md) MUST be
        //# created for each AWS KMS client by initializing each keyring with
        .map((client) => {
          /* Postcondition: If the configured clientProvider is not able to create a client for a defined region, throw an error. */
          needs(
            client,
            'Configured clientProvider is unable to create a client for a configured region.'
          )
          return new MrkAwareDiscoveryKeyring({
            client,
            discoveryFilter,
            grantTokens,
          })
        })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
    //# by using this set of discovery keyrings as the child keyrings
    //# (../multi-keyring.md#child-keyrings).
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //# This Multi-Keyring MUST be
    //# this functions output.
    return new MultiKeyring({ children })
  }
}
