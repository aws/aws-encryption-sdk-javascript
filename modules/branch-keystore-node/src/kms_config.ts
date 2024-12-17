// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  isMultiRegionAwsKmsArn,
  // getRegionFromIdentifier,
  parseAwsKmsKeyArn,
} from '@aws-crypto/kms-keyring'
import {
  constructArnInOtherRegion,
  mrkAwareAwsKmsKeyIdCompare,
  ParsedAwsKmsKeyArn,
} from '@aws-crypto/kms-keyring'
import { needs, readOnlyProperty } from '@aws-crypto/material-management'

//= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
//# Both `KMS Key ARN` and `KMS MRKey ARN` accept MRK or regular Single Region KMS ARNs.
export interface KMSSingleRegionKey {
  identifier: string
}
export interface KMSMultiRegionKey {
  mrkIdentifier: string
}

//= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
//# `Discovery` does not take an additional argument.
export type Discovery = 'discovery'

//= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
//= type=implication
//# `MRDiscovery` MUST take an additional argument, which is a region.
export interface MrDiscovery {
  region: string
}

//= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
//# This configures the Keystore's KMS Key ARN restrictions,
//# which determines which KMS Key(s) is used
//# to wrap and unwrap the keys stored in Amazon DynamoDB.
//# There are four (4) options:
//#
//# - Discovery
//# - MRDiscovery
//# - Single Region Key Compatibility, denoted as `KMS Key ARN`
//# - Multi Region Key Compatibility, denoted as `KMS MRKey ARN`
export type KmsConfig =
  | KMSSingleRegionKey
  | KMSMultiRegionKey
  | Discovery
  | MrDiscovery

// an interface to outline the common operations any of the 3 region-based AWS KMS
// configurations should perform
export interface RegionalKmsConfig {
  /**
   * this method tells the user the config's region
   * @returns the region
   */
  getRegion(): string

  /**
   * this method tells the user if the config is compatible with an arn
   * @param otherArn
   * @returns a flag answering the method's purpose
   */
  isCompatibleWithArn(otherArn: string): boolean
}

// an abstract class defining common behavior for operations that SRK and MRK compatibility
// configs should perform
export class KmsKeyConfig implements RegionalKmsConfig {
  public declare readonly _parsedArn: ParsedAwsKmsKeyArn
  public declare readonly _arn: string
  public declare readonly _mrkRegion: string
  public declare readonly _config: KmsConfig

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
  //# `KMS Key ARN` and `KMS MRKey ARN` MUST take an additional argument
  //# that is a KMS ARN.
  constructor(config: KmsConfig) {
    readOnlyProperty(this, '_config', config)
    /* Precondition: config must be a string or object */
    const configType = typeof config
    needs(
      !!config && (configType === 'object' || configType === 'string'),
      'Config must be a `discovery` or an object.'
    )

    if (configType === 'string') {
      /* Precondition: Only `discovery` is a valid string value */
      needs(config === 'discovery', 'Unexpected config shape')
    } else if (
      'identifier' in (config as any) ||
      'mrkIdentifier' in (config as any)
    ) {
      const arn =
        'identifier' in (config as any)
          ? (config as any).identifier
          : (config as any).mrkIdentifier
      /* Precondition: ARN must be a string */
      needs(typeof arn === 'string', 'ARN must be a string')

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
      //# To be clear, an KMS ARN for a Multi-Region Key MAY be provided to the `KMS Key ARN` configuration,
      //# and a KMS ARN for non Multi-Region Key MAY be provided to the `KMS MRKey ARN` configuration.

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
      //# This ARN MUST NOT be an Alias.
      //# This ARN MUST be a valid
      //# [AWS KMS Key ARN](./aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn).
      const parsedArn = parseAwsKmsKeyArn(arn)
      needs(
        parsedArn && parsedArn.ResourceType === 'key',
        `${arn} must be a well-formed AWS KMS non-alias resource arn`
      )

      readOnlyProperty(this, '_parsedArn', parsedArn)
      readOnlyProperty(this, '_arn', arn)
    } else if ('region' in (config as any)) {
      readOnlyProperty(this, '_mrkRegion', (config as any).region)
    } else {
      needs(false, 'Unexpected config shape')
    }

    Object.freeze(this)
  }

  getRegion(): string {
    if (this._config === 'discovery') {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If a DDB client needs to be constructed and the AWS KMS Configuration is Discovery,
      //# a new DynamoDb client MUST be created with the default configuration.

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If AWS KMS client needs to be constructed and the AWS KMS Configuration is Discovery,
      //# a new AWS KMS client MUST be created with the default configuration.
      return ''
    } else if (
      'identifier' in this._config ||
      'mrkIdentifier' in this._config
    ) {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If a DDB client needs to be constructed and the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
      //# a new DynamoDb client MUST be created with the region of the supplied KMS ARN.

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If AWS KMS client needs to be constructed and the AWS KMS Configuration is KMS Key ARN or KMS MRKey ARN,
      //# a new AWS KMS client MUST be created with the region of the supplied KMS ARN.
      return this._parsedArn.Region
    } else if ('region' in this._config) {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If a DDB client needs to be constructed and the AWS KMS Configuration is MRDiscovery,
      //# a new DynamoDb client MUST be created with the region configured in the MRDiscovery.

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#initialization
      //# If AWS KMS client needs to be constructed and the AWS KMS Configuration is MRDiscovery,
      //# a new AWS KMS client MUST be created with the region configured in the MRDiscovery.
      return this._mrkRegion
    } else {
      needs(false, 'Unexpected configuration state')
    }
  }

  isCompatibleWithArn(otherArn: string): boolean {
    if (this._config === 'discovery' || 'region' in this._config) {
      // This may result in the function being called twice.
      // However this is the most correct behavior

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `Discovery` or `MRDiscovery`,
      //# the `kms-arn` field of DDB response item MUST NOT be an Alias
      //# or the operation MUST fail.
      const parsedArn = parseAwsKmsKeyArn(otherArn)
      needs(
        parsedArn && parsedArn.ResourceType === 'key',
        `${otherArn} must be a well-formed AWS KMS non-alias resource arn`
      )

      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-key-arn-compatibility
      //# If the [AWS KMS Configuration](#aws-kms-configuration) is Discovery or MRDiscovery,
      //# no comparison is ever made between ARNs.
      return true
    } else if ('identifier' in this._config) {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-key-arn-compatibility
      //# For two ARNs to be compatible:
      //#
      //# If the [AWS KMS Configuration](#aws-kms-configuration) designates single region ARN compatibility,
      //# then two ARNs are compatible if they are exactly equal.
      return this._arn === otherArn
    } else if ('mrkIdentifier' in this._config) {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-key-arn-compatibility
      //# If the [AWS KMS Configuration](#aws-kms-configuration) designates MRK ARN compatibility,
      //# then two ARNs are compatible if they are equal in all parts other than the region.
      //# That is, they are compatible if [AWS KMS MRK Match for Decrypt](aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation) returns true.
      return mrkAwareAwsKmsKeyIdCompare(this._arn, otherArn)
    } else {
      needs(false, 'Unexpected configuration state')
    }
  }

  getCompatibleArnArn(otherArn: string): string {
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
    //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `KMS Key ARN` or `KMS MRKey ARN`,
    //# the `kms-arn` field of the DDB response item MUST be
    //# [compatible with](#aws-key-arn-compatibility) the configured KMS Key in
    //# the [AWS KMS Configuration](#aws-kms-configuration) for this keystore,
    //# or the operation MUST fail.

    //# If the Keystore's [AWS KMS Configuration](#aws-kms-configuration) is `Discovery` or `MRDiscovery`,
    //# the `kms-arn` field of DDB response item MUST NOT be an Alias
    //# or the operation MUST fail.
    needs(
      this.isCompatibleWithArn(otherArn),
      'KMS ARN from DDB response item MUST be compatible with the configured KMS Key in the AWS KMS Configuration for this keystore'
    )

    if (this._config == 'discovery') {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //# - `KeyId`, if the KMS Configuration is Discovery, MUST be the `kms-arn` attribute value of the AWS DDB response item.
      return otherArn
    } else if ('region' in this._config) {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //# If the KMS Configuration is MRDiscovery, `KeyId` MUST be the `kms-arn` attribute value of the AWS DDB response item, with the region replaced by the configured region.
      const parsedArn = parseAwsKmsKeyArn(otherArn)
      needs(parsedArn, 'KMS ARN from the keystore is not an ARN:' + otherArn)
      return isMultiRegionAwsKmsArn(parsedArn)
        ? constructArnInOtherRegion(parsedArn, this._mrkRegion)
        : otherArn
    } else if (
      'identifier' in this._config ||
      'mrkIdentifier' in this._config
    ) {
      //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-branch-key-decryption
      //# Otherwise, it MUST BE the Keystore's configured KMS Key.

      // In this case, the equality condition has already been satisfied.
      // In the SRK case this is strict equality,
      // in the MKR case this is functional (everything but region)
      return this._arn
    } else {
      // This is for completeness.
      // It should should be impossible to get here.
      needs(false, 'Unexpected configuration state')
    }
  }
}
