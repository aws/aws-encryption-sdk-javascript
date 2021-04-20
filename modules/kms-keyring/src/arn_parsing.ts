// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { needs } from '@aws-crypto/material-management'

/* See: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms
 * regex to match: 'resourceType/resourceId' || 'resourceType'
 * This is complicated because the `split(':')`.
 * The valid resourceType resourceId delimiters are `/`, `:`.
 * This means if the delimiter is a `:` it will be split out,
 * when splitting the whole arn.
 */
export const KMS_SERVICE = 'kms'

export type ParsedAwsKmsKeyArn = {
  Partition: string
  Region: string
  AccountId: string
  ResourceType: string
  ResourceId: string
}

const ARN_PREFIX = 'arn'
const KEY_RESOURCE_TYPE = 'key'
const ALIAS_RESOURCE_TYPE = 'alias'
const MRK_RESOURCE_ID_PREFIX = 'mrk-'

const VALID_RESOURCE_TYPES = [KEY_RESOURCE_TYPE, ALIAS_RESOURCE_TYPE]

/**
 * Returns a parsed ARN if a valid AWS KMS Key ARN.
 * If the request is a valid resource the function
 * will return false.
 * However if the ARN is malformed this function throws an error,
 */
export function parseAwsKmsKeyArn(
  kmsKeyArn: string
): ParsedAwsKmsKeyArn | false {
  /* Precondition: A KMS Key Id must be a non-null string. */
  needs(
    kmsKeyArn && typeof kmsKeyArn === 'string',
    'KMS key arn must be a non-null string.'
  )

  const parts = kmsKeyArn.split(':')

  /* Check for early return (Postcondition): A valid ARN has 6 parts. */
  if (parts.length === 1) {
    /* Exceptional Postcondition: Only a valid AWS KMS resource.
     * This may result in this function being called twice.
     * However this is the most correct behavior.
     */
    parseAwsKmsResource(kmsKeyArn)
    return false
  }

  /* See: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms
   * arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
   * arn:aws:kms:us-east-1:123456789012:alias/example-alias
   */
  const [
    arnLiteral,
    partition,
    service,
    region = '',
    account = '',
    resource = '',
  ] = parts

  const [resourceType, ...resourceSection] = resource.split('/')

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
  //# The resource section MUST be non-empty and MUST be split by a
  //# single "/" any additional "/" are included in the resource id
  const resourceId = resourceSection.join('/')

  /* If this is a valid AWS KMS Key ARN, return the parsed ARN */
  needs(
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //# MUST start with string "arn"
    arnLiteral === ARN_PREFIX &&
      //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
      //# The partition MUST be a non-empty
      partition &&
      //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
      //# The service MUST be the string "kms"
      service === KMS_SERVICE &&
      //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
      //# The region MUST be a non-empty string
      region &&
      //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
      //# The account MUST be a non-empty string
      account &&
      //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
      //# The resource type MUST be either "alias" or "key"
      VALID_RESOURCE_TYPES.includes(resourceType) &&
      //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
      //# The resource id MUST be a non-empty string
      resourceId,
    'Malformed arn.'
  )
  return {
    Partition: partition,
    Region: region,
    AccountId: account,
    ResourceType: resourceType,
    ResourceId: resourceId,
  }
}

export function getRegionFromIdentifier(kmsKeyIdentifier: string): string {
  const awsKmsKeyArn = parseAwsKmsKeyArn(kmsKeyIdentifier)
  return awsKmsKeyArn ? awsKmsKeyArn.Region : ''
}

export function parseAwsKmsResource(
  resource: string
): Pick<ParsedAwsKmsKeyArn, 'ResourceType' | 'ResourceId'> {
  /* Precondition: An AWS KMS resource can not have a `:`.
   * That would make it an ARNlike.
   */
  needs(resource.split(':').length === 1, 'Malformed resource.')

  /* `/` is a valid values in an AWS KMS Alias name. */
  const [head, ...tail] = resource.split('/')

  /* Precondition: A raw identifer is only an alias or a key. */
  needs(head === ALIAS_RESOURCE_TYPE || !tail.length, 'Malformed resource.')

  const [resourceType, resourceId] =
    head === ALIAS_RESOURCE_TYPE
      ? [ALIAS_RESOURCE_TYPE, tail.join('/')]
      : [KEY_RESOURCE_TYPE, head]

  return {
    ResourceType: resourceType,
    ResourceId: resourceId,
  }
}

export function validAwsKmsIdentifier(
  kmsKeyIdentifier: string
):
  | ParsedAwsKmsKeyArn
  | Pick<ParsedAwsKmsKeyArn, 'ResourceType' | 'ResourceId'> {
  return (
    parseAwsKmsKeyArn(kmsKeyIdentifier) || parseAwsKmsResource(kmsKeyIdentifier)
  )
}

//= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
//# This function MUST take a single AWS KMS ARN
export function isMultiRegionAwsKmsArn(
  kmsIdentifier: string | ParsedAwsKmsKeyArn
): boolean {
  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //# If the input is an invalid AWS KMS ARN this function MUST error.
  const awsKmsKeyArn =
    typeof kmsIdentifier === 'string'
      ? parseAwsKmsKeyArn(kmsIdentifier)
      : kmsIdentifier

  /* Precondition: The kmsIdentifier must be an ARN. */
  needs(awsKmsKeyArn, 'AWS KMS identifier is not an ARN')

  const { ResourceType, ResourceId } = awsKmsKeyArn

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //# If resource type is "alias", this is an AWS KMS alias ARN and MUST
  //# return false.
  //
  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //# If resource type is "key" and resource ID starts with
  //# "mrk-", this is a AWS KMS multi-Region key ARN and MUST return true.
  //
  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //# If resource type is "key" and resource ID does not start with "mrk-",
  //# this is a (single-region) AWS KMS key ARN and MUST return false.
  return (
    ResourceType === KEY_RESOURCE_TYPE &&
    ResourceId.startsWith(MRK_RESOURCE_ID_PREFIX)
  )
}

//= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
//# This function MUST take a single AWS KMS identifier
export function isMultiRegionAwsKmsIdentifier(kmsIdentifier: string): boolean {
  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
  //# If the input starts with "arn:", this MUST return the output of
  //# identifying an an AWS KMS multi-Region ARN (aws-kms-key-
  //# arn.md#identifying-an-an-aws-kms-multi-region-arn) called with this
  //# input.
  if (kmsIdentifier.startsWith('arn:')) {
    return isMultiRegionAwsKmsArn(kmsIdentifier)
  } else if (kmsIdentifier.startsWith('alias/')) {
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //# If the input starts with "alias/", this an AWS KMS alias and
    //# not a multi-Region key id and MUST return false.
    return false
  } else if (kmsIdentifier.startsWith(MRK_RESOURCE_ID_PREFIX)) {
    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
    //# If the input starts
    //# with "mrk-", this is a multi-Region key id and MUST return true.
    return true
  }
  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
  //# If
  //# the input does not start with any of the above, this is not a multi-
  //# Region key id and MUST return false.
  return false
}

/* Returns a boolean representing whether two AWS KMS Key IDs should be considered equal.
 * For everything except MRK-indicating ARNs, this is a direct comparison.
 * For MRK-indicating ARNs, this is a comparison of every ARN component except region.
 * Throws an error if the IDs are not explicitly equal and at least one of the IDs
 * is not a valid AWS KMS Key ARN or alias name.
 */
//= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
//# The caller MUST provide:
export function mrkAwareAwsKmsKeyIdCompare(
  keyId1: string,
  keyId2: string
): boolean {
  //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
  //# If both identifiers are identical, this function MUST return "true".
  if (keyId1 === keyId2) return true

  //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
  //# Otherwise if either input is not identified as a multi-Region key
  //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
  //# this function MUST return "false".
  const arn1 = parseAwsKmsKeyArn(keyId1)
  const arn2 = parseAwsKmsKeyArn(keyId2)
  if (!arn1 || !arn2) return false
  if (!isMultiRegionAwsKmsArn(arn1) || !isMultiRegionAwsKmsArn(arn2))
    return false

  //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
  //# Otherwise if both inputs are
  //# identified as a multi-Region keys (aws-kms-key-arn.md#identifying-an-
  //# aws-kms-multi-region-key), this function MUST return the result of
  //# comparing the "partition", "service", "accountId", "resourceType",
  //# and "resource" parts of both ARN inputs.
  return (
    arn1.Partition === arn2.Partition &&
    arn1.AccountId === arn2.AccountId &&
    arn1.ResourceType === arn2.ResourceType &&
    arn1.ResourceId === arn2.ResourceId
  )
}

/* Manually construct a new MRK ARN that looks like the old ARN except the region is replaced by a new region.
 * Throws an error if the input parsed ARN is not an MRK
 */
export function constructArnInOtherRegion(
  parsedArn: ParsedAwsKmsKeyArn,
  region: string
): string {
  /* Precondition: Only reconstruct a multi region ARN. */
  needs(
    isMultiRegionAwsKmsArn(parsedArn),
    'Cannot attempt to construct an ARN in a new region from an non-MRK ARN.'
  )
  const { Partition, AccountId, ResourceType, ResourceId } = parsedArn
  return [
    ARN_PREFIX,
    Partition,
    KMS_SERVICE,
    region,
    AccountId,
    ResourceType + '/' + ResourceId,
  ].join(':')
}
