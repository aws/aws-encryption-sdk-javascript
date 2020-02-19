/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { needs } from '@aws-crypto/material-management'

/* See: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms
 * regex to match: 'resourceType/resourceId' || 'resourceType'
 * This is complicated because the `split(':')`.
 * The valid resourceType resourceId delimiters are `/`, `:`.
 * This means if the delimiter is a `:` it will be split out,
 * when splitting the whole arn.
 */
const aliasOrKeyResourceType = /^(alias|key)(\/.*)*$/

export function regionFromKmsKeyArn (kmsKeyArn: string): string {
  /* Precondition: A KMS key arn must be a string. */
  needs(typeof kmsKeyArn === 'string', 'KMS key arn must be a string.')

  /* See: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms
   * arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
   * arn:aws:kms:us-east-1:123456789012:alias/example-alias
   */
  const [arnLiteral, partition, service, region = ''] = kmsKeyArn.split(':')

  /* Postcondition: The ARN must be well formed.
   * The arn and kms section have defined values,
   * but the aws section does not.
   * It is also possible to have a a key or alias.
   * In this case the partition, service, region
   * will be empty.
   * In this case the arnLiteral should look like an alias.
   */
  needs(
    (arnLiteral === 'arn' &&
      partition &&
      service === 'kms' &&
      region) ||
    /* Partition may or may not have a value.
     * If the resourceType delimiter is /,
     * it will not have a value.
     * However if the delimiter is : it will
     * because of the split(':')
     */
    (!service &&
      !region &&
      arnLiteral.match(aliasOrKeyResourceType)),
    'Malformed arn.')

  return region
}
