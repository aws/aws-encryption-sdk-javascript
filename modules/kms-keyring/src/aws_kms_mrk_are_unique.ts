// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { isMultiRegionAwsKmsIdentifier, parseAwsKmsKeyArn } from './arn_parsing'

//= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
//# The caller MUST provide:
export function awsKmsMrkAreUnique(awsKmsIdentifers: string[]): void {
  const multiRegionKeys = awsKmsIdentifers.filter((i) =>
    isMultiRegionAwsKmsIdentifier(i)
  )

  //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
  //# If the list does not contain any multi-Region keys (aws-kms-key-
  //# arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
  //# exit successfully.
  if (!multiRegionKeys.length) return

  const multiRegionKeyIds = multiRegionKeys.map((mrk) => {
    const arn = parseAwsKmsKeyArn(mrk)
    return arn ? arn.ResourceId : mrk
  })
  //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
  //# If there are zero duplicate resource ids between the multi-region
  //# keys, this function MUST exit successfully
  if (new Set(multiRegionKeyIds).size === multiRegionKeys.length) return

  //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
  //# If any duplicate multi-region resource ids exist, this function MUST
  //# yield an error that includes all identifiers with duplicate resource
  //# ids not only the first duplicate found.
  const duplicateMultiRegionIdentifiers = multiRegionKeyIds
    .map((mrk, i, a) => {
      if (a.indexOf(mrk) !== a.lastIndexOf(mrk)) return multiRegionKeys[i]
      /* Postcondition: Remove non-duplicate multi-Region keys. */
      return false
    })
    .filter((dup) => dup)
    .join(',')

  throw new Error(
    `Related multi-Region keys: ${duplicateMultiRegionIdentifiers} are not allowed.`
  )
}
