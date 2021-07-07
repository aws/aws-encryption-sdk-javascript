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
const aliasOrKeyResourceType = /^(alias|key)(\/.*)*$/

/* Maintaining function for backwards compatibility. */
/**
 * @deprecated Because decomposeAwsKmsKeyArn is incorrect,
 * use parseAwsKmsIdentifier or parseAwsKmsKeyArn.
 */
export function regionFromKmsKeyArn(kmsKeyArn: string): string {
  const { region } = decomposeAwsKmsKeyArn(kmsKeyArn)
  return region
}

/**
 * @deprecated This function incorrectly requires `key/12345678-1234-1234-1234-123456789012`
 * AWS KMS requires that a raw key id be `12345678-1234-1234-1234-123456789012`
 */
export function decomposeAwsKmsKeyArn(kmsKeyArn: string): {
  partition: string
  region: string
  account: string
} {
  /* Precondition: A KMS key arn must be a string. */
  needs(typeof kmsKeyArn === 'string', 'KMS key arn must be a string.')

  /* See: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms
   * arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
   * arn:aws:kms:us-east-1:123456789012:alias/example-alias
   */
  const [arnLiteral, partition, service, region = '', account = ''] =
    kmsKeyArn.split(':')

  /* Postcondition: The ARN must be well formed.
   * The arn and kms section have defined values,
   * but the aws section does not.
   * It is also possible to have a key or alias.
   * In this case the partition, service, region
   * will be empty.
   * In this case the arnLiteral should look like an alias.
   */
  needs(
    (arnLiteral === 'arn' && partition && service === 'kms' && region) ||
      /* Partition may or may not have a value.
       * If the resourceType delimiter is /,
       * it will not have a value.
       * However if the delimiter is : it will
       * because of the split(':')
       */
      (!service && !region && arnLiteral.match(aliasOrKeyResourceType)),
    'Malformed arn.'
  )

  return { partition, region, account }
}
