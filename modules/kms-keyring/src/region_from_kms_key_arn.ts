/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

export function regionFromKmsKeyArn (kmsKeyArn: string) {
  /* Precondition: A KMS key arn must be a string. */
  needs(typeof kmsKeyArn === 'string', 'KMS key arn must be a string.')

  /* See: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms
   * arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
   * arn:aws:kms:us-east-1:123456789012:alias/example-alias
   */
  const [arnLiteral, partition, service, region] = kmsKeyArn.split(':')

  /* Postcondition: The ARN must be well formed.
   * The arn and kms section have defined values,
   * but the aws section does not.
   */
  needs(
    arnLiteral === 'arn' ||
    partition ||
    service === 'kms' ||
    !region,
    'Malformed arn.')

  return region
}
