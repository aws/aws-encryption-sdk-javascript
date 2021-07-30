// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  constructArnInOtherRegion,
  isMultiRegionAwsKmsArn,
  mrkAwareAwsKmsKeyIdCompare,
  parseAwsKmsKeyArn,
  parseAwsKmsResource,
  validAwsKmsIdentifier,
  isMultiRegionAwsKmsIdentifier,
} from '../src/arn_parsing'

describe('parseAwsKmsKeyArn', () => {
  it('parses a valid ARN', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    const parsedKeyArn = parseAwsKmsKeyArn(keyId)
    expect(parsedKeyArn && parsedKeyArn.Partition).to.equal('aws')
    expect(parsedKeyArn && parsedKeyArn.Region).to.equal('us-east-1')
    expect(parsedKeyArn && parsedKeyArn.AccountId).to.equal('123456789012')
    expect(parsedKeyArn && parsedKeyArn.ResourceType).to.equal('key')
    expect(parsedKeyArn && parsedKeyArn.ResourceId).to.equal(
      '12345678-1234-1234-1234-123456789012'
    )
  })

  it('parses a valid MRK ARN', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const parsedKeyArn = parseAwsKmsKeyArn(keyId)
    expect(parsedKeyArn && parsedKeyArn.Partition).to.equal('aws')
    expect(parsedKeyArn && parsedKeyArn.Region).to.equal('us-east-1')
    expect(parsedKeyArn && parsedKeyArn.AccountId).to.equal('123456789012')
    expect(parsedKeyArn && parsedKeyArn.ResourceType).to.equal('key')
    expect(parsedKeyArn && parsedKeyArn.ResourceId).to.equal(
      'mrk-12345678123412341234123456789012'
    )
  })

  it('parses a valid alias ARN', async () => {
    const keyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const parsedKeyArn = parseAwsKmsKeyArn(keyId)
    expect(parsedKeyArn && parsedKeyArn.Partition).to.equal('aws')
    expect(parsedKeyArn && parsedKeyArn.Region).to.equal('us-east-1')
    expect(parsedKeyArn && parsedKeyArn.AccountId).to.equal('123456789012')
    expect(parsedKeyArn && parsedKeyArn.ResourceType).to.equal('alias')
    expect(parsedKeyArn && parsedKeyArn.ResourceId).to.equal('example-alias')
  })

  it('Precondition: A KMS Key Id must be a non-null string.', async () => {
    const bad = {} as any
    expect(() => parseAwsKmsKeyArn(bad)).to.throw(
      'KMS key arn must be a non-null string.'
    )
    expect(() => parseAwsKmsKeyArn('')).to.throw(
      'KMS key arn must be a non-null string.'
    )
  })

  it('Exceptional Postcondition: Only a valid AWS KMS resource.', () => {
    expect(() => parseAwsKmsKeyArn('not/an/alias')).to.throw(
      'Malformed resource.'
    )
  })

  it('Check for early return (Postcondition): A valid ARN has 6 parts.', async () => {
    expect(parseAwsKmsKeyArn('mrk-12345678123412341234123456789012')).to.equal(
      false
    )
  })

  it('AWS KMS only accepts / as a resource delimiter.', async () => {
    const keyId = 'alias:example-alias'
    expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
  })

  it('returns false on a valid alias with "/"', async () => {
    const keyId = 'alias/example-alias'
    expect(parseAwsKmsKeyArn(keyId)).to.equal(false)
  })

  it('throws an error for an invalid KeyId', async () => {
    const keyId = 'Not:an/arn'
    expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
  //= type=test
  //# MUST start with string "arn"
  it('throws an error for an ARN that does not start with arn', async () => {
    const keyId =
      'arn-not:aws:not-kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
  //= type=test
  //# The partition MUST be a non-empty
  it('throws an error for a missing partition ARN', async () => {
    const keyId =
      'arn::kms::123456789012:key/12345678-1234-1234-1234-123456789012'
    expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
  //= type=test
  //# The service MUST be the string "kms"
  it('throws an error for an ARN without kms as service', async () => {
    const keyId =
      'arn:aws:not-kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
  //= type=test
  //# The region MUST be a non-empty string
  it('throws an error for a missing region ARN', async () => {
    const keyId =
      'arn:aws:kms::123456789012:key/12345678-1234-1234-1234-123456789012'
    expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
  //= type=test
  //# The account MUST be a non-empty string
  it('throws an error for a missing account ARN', async () => {
    const keyId =
      'arn:aws:kms:us-east-1::key/12345678-1234-1234-1234-123456789012'
    expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
  //= type=test
  //# The resource section MUST be non-empty and MUST be split by a
  //# single "/" any additional "/" are included in the resource id
  describe('Resource section', () => {
    it('throws if the resource is missing', async () => {
      const keyId = 'arn:aws:kms:us-east-1:123456789012:'
      expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
    })

    it('throws if the resource is delimited with ":".', async () => {
      const keyId =
        'arn:aws:kms:us-east-1:123456789012:key:12345678-1234-1234-1234-123456789012'
      expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
    })

    it('an alias can contain slashes', async () => {
      const keyId =
        'arn:aws:kms:us-east-1:123456789012:alias/with/extra/slashes'
      const { ResourceId } = parseAwsKmsKeyArn(keyId) || {}
      expect(ResourceId).to.equal('with/extra/slashes')
    })

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The resource type MUST be either "alias" or "key"
    it('throws if the resource type is not alias or key', async () => {
      const keyId =
        'arn:aws:kms:us-east-1:123456789012:key-not/12345678-1234-1234-1234-123456789012'
      expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
    })

    //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.5
    //= type=test
    //# The resource id MUST be a non-empty string
    it('throws if the resource id is missing', async () => {
      const keyId = 'arn:aws:kms:us-east-1:123456789012:key'
      expect(() => parseAwsKmsKeyArn(keyId)).to.throw('Malformed arn.')
    })
  })
})

describe('isMultiRegionAwsKmsArn', () => {
  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //= type=test
  //# This function MUST take a single AWS KMS ARN
  //
  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //= type=test
  //# If resource type is "key" and resource ID starts with
  //# "mrk-", this is a AWS KMS multi-Region key ARN and MUST return true.
  it('returns true for an MRK ARN', async () => {
    const key =
      'arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123412341234123456789012'
    expect(isMultiRegionAwsKmsArn(key)).to.equal(true)
    // @ts-expect-error should be a valid arn
    expect(isMultiRegionAwsKmsArn(parseAwsKmsKeyArn(key))).to.equal(true)
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //= type=test
  //# If the input is an invalid AWS KMS ARN this function MUST error.
  it('invalid arn will throw', () => {
    expect(() => isMultiRegionAwsKmsArn('Not:an/arn')).to.throw(
      'Malformed arn.'
    )
  })

  it('Precondition: The kmsIdentifier must be an ARN.', () => {
    expect(() =>
      isMultiRegionAwsKmsArn('mrk-12345678123412341234123456789012')
    ).to.throw('AWS KMS identifier is not an ARN')
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //= type=test
  //# If resource type is "alias", this is an AWS KMS alias ARN and MUST
  //# return false.
  it('returns false for an alias ARN with "mrk-"', async () => {
    const key =
      'arn:aws:kms:us-west-2:123456789012:alias/mrk-12345678123412341234123456789012'
    expect(isMultiRegionAwsKmsArn(key)).to.equal(false)
    // @ts-expect-error should be a valid arn
    expect(isMultiRegionAwsKmsArn(parseAwsKmsKeyArn(key))).to.equal(false)
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.8
  //= type=test
  //# If resource type is "key" and resource ID does not start with "mrk-",
  //# this is a (single-region) AWS KMS key ARN and MUST return false.
  it('returns false for a non-MRK ARN', async () => {
    const key =
      'arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012'
    expect(isMultiRegionAwsKmsArn(key)).to.equal(false)
    // @ts-expect-error should be a valid arn
    expect(isMultiRegionAwsKmsArn(parseAwsKmsKeyArn(key))).to.equal(false)
  })
})

describe('isMultiRegionAwsKmsIdentifier', () => {
  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
  //= type=test
  //# This function MUST take a single AWS KMS identifier
  it('can identify an ARN', () => {
    const key =
      'arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123412341234123456789012'
    expect(isMultiRegionAwsKmsIdentifier(key)).to.equal(true)
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
  //= type=test
  //# If the input starts with "arn:", this MUST return the output of
  //# identifying an an AWS KMS multi-Region ARN (aws-kms-key-
  //# arn.md#identifying-an-an-aws-kms-multi-region-arn) called with this
  //# input.
  it('can identify and arn', () => {
    const key =
      'arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123412341234123456789012'
    expect(isMultiRegionAwsKmsIdentifier(key)).to.equal(true)
    const arn = 'arn:aws:dynamodb:us-east-2:123456789012:table/myDynamoDBTable'
    expect(() => isMultiRegionAwsKmsIdentifier(arn)).to.throw('Malformed arn.')
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
  //= type=test
  //# If the input starts with "alias/", this an AWS KMS alias and
  //# not a multi-Region key id and MUST return false.
  it('is not confused by an alias', () => {
    const alias = 'alias/mrk-12345678123412341234123456789012'
    expect(isMultiRegionAwsKmsIdentifier(alias)).to.equal(false)
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
  //= type=test
  //# If the input starts
  //# with "mrk-", this is a multi-Region key id and MUST return true.
  it('identifed a raw mulit region key resource', () => {
    const keyId = 'mrk-12345678123412341234123456789012'
    expect(isMultiRegionAwsKmsIdentifier(keyId)).to.equal(true)
  })

  //= compliance/framework/aws-kms/aws-kms-key-arn.txt#2.9
  //= type=test
  //# If
  //# the input does not start with any of the above, this is not a multi-
  //# Region key id and MUST return false.
  it('is not confused by a single region key', () => {
    const keyId = 'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
    expect(isMultiRegionAwsKmsIdentifier(keyId)).to.equal(false)
  })
})

describe('mrkAwareAwsKmsKeyIdCompare', () => {
  //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
  //= type=test
  //# The caller MUST provide:
  //
  //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
  //= type=test
  //# If both identifiers are identical, this function MUST return "true".
  it('returns true comparing two identical IDs', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    expect(mrkAwareAwsKmsKeyIdCompare(keyId, keyId)).to.equal(true)
    const keyAlias = 'alias/someAlias'
    expect(mrkAwareAwsKmsKeyIdCompare(keyAlias, keyAlias)).to.equal(true)
  })

  it('returns true comparing two MRK ARNs that are identical except region', async () => {
    const usEast1Key =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const usWest2Key =
      'arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123412341234123456789012'
    expect(mrkAwareAwsKmsKeyIdCompare(usEast1Key, usWest2Key)).to.equal(true)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
  //= type=test
  //# Otherwise if either input is not identified as a multi-Region key
  //# (aws-kms-key-arn.md#identifying-an-aws-kms-multi-region-key), then
  //# this function MUST return "false".
  it('returns false for different identifiers that are not multi-Region keys.', () => {
    expect(
      mrkAwareAwsKmsKeyIdCompare(
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-1:123456789012:key/12345678-1234-1234-1234-123456789012'
      )
    ).to.equal(false)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-match-for-decrypt.txt#2.5
  //= type=test
  //# Otherwise if both inputs are
  //# identified as a multi-Region keys (aws-kms-key-arn.md#identifying-an-
  //# aws-kms-multi-region-key), this function MUST return the result of
  //# comparing the "partition", "service", "accountId", "resourceType",
  //# and "resource" parts of both ARN inputs.
  it('returns false comparing two MRK ARNs that differ in more than region', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const otherAccountKey =
      'arn:aws:kms:us-east-1:000000000000:key/mrk-12345678123412341234123456789012'
    const otherPartitionKey =
      'arn:not-aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const otherResource =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-00000000-0000-0000-0000-000000000000'
    expect(mrkAwareAwsKmsKeyIdCompare(keyId, otherAccountKey)).to.equal(false)
    expect(mrkAwareAwsKmsKeyIdCompare(keyId, otherPartitionKey)).to.equal(false)
    expect(mrkAwareAwsKmsKeyIdCompare(keyId, otherResource)).to.equal(false)
  })

  it('returns false comparing an alias with a key ARN', async () => {
    const keyAlias = 'alias/SomeKeyAlias'
    const keyId =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const keyAliasArn = 'arn:aws:kms:us-east-1:123456789012:alias/SomeKeyAlias'
    expect(mrkAwareAwsKmsKeyIdCompare(keyAlias, keyId)).to.equal(false)
    expect(mrkAwareAwsKmsKeyIdCompare(keyAlias, keyAliasArn)).to.equal(false)
  })

  it('returns false comparing two distinct aliases', async () => {
    const keyAlias = 'alias/SomeKeyAlias'
    const otherKeyAlias = 'alias/SomeOtherKeyAlias'
    expect(mrkAwareAwsKmsKeyIdCompare(keyAlias, otherKeyAlias)).to.equal(false)
  })

  it('throws an error comparing an invalid ID', async () => {
    const keyId =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    const badId = 'Not:an/Arn'
    expect(() => mrkAwareAwsKmsKeyIdCompare(keyId, badId)).to.throw()
  })
})

describe('parseAwsKmsResource', () => {
  it('basic use', () => {
    const info = parseAwsKmsResource('12345678-1234-1234-1234-123456789012')
    expect(info.ResourceId).to.equal('12345678-1234-1234-1234-123456789012')
    expect(info.ResourceType).to.equal('key')
  })

  it('works on an alias', () => {
    const info = parseAwsKmsResource('alias/my-alias')
    expect(info.ResourceId).to.equal('my-alias')
    expect(info.ResourceType).to.equal('alias')
  })

  it('works on an alias', () => {
    const info = parseAwsKmsResource('alias/my/alias/with/slashes')
    expect(info.ResourceId).to.equal('my/alias/with/slashes')
    expect(info.ResourceType).to.equal('alias')
  })

  it('Precondition: An AWS KMS resource can not have a `:`.', () => {
    const keyId =
      'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
    expect(() => parseAwsKmsResource(keyId)).to.throw('Malformed resource.')
  })

  it('Precondition: A raw identifer is only an alias or a key.', () => {
    expect(() => parseAwsKmsResource('anything/with a slash')).to.throw(
      'Malformed resource.'
    )
  })
})

describe('validAwsKmsIdentifier', () => {
  it('is able to parse valid identifiers', () => {
    expect(
      !!validAwsKmsIdentifier(
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
      )
    ).to.equal(true)
    expect(
      !!validAwsKmsIdentifier(
        'arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
      )
    ).to.equal(true)
    expect(
      !!validAwsKmsIdentifier(
        'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
      )
    ).to.equal(true)
    expect(!!validAwsKmsIdentifier('alias/my/alias/with/slashes')).to.equal(
      true
    )
    expect(
      !!validAwsKmsIdentifier('12345678-1234-1234-1234-123456789012')
    ).to.equal(true)
    expect(
      !!validAwsKmsIdentifier('mrk-80bd8ecdcd4342aebd84b7dc9da498a7')
    ).to.equal(true)
  })

  it('throws for invalid identifiers', () => {
    expect(() => validAwsKmsIdentifier('Not:an/arn')).to.throw('Malformed arn')
    expect(() => validAwsKmsIdentifier('alias:no')).to.throw('Malformed arn')
    expect(() =>
      validAwsKmsIdentifier(
        'arn:aws:dynamodb:us-east-2:123456789012:table/myDynamoDBTable'
      )
    ).to.throw('Malformed arn')
    expect(() => validAwsKmsIdentifier('')).to.throw(
      'KMS key arn must be a non-null string.'
    )
  })
})

describe('constructArnInOtherRegion', () => {
  it('returns new ARN with region replaced', async () => {
    const parsedArn = {
      Partition: 'aws',
      Region: 'us-west-2',
      AccountId: '123456789012',
      ResourceType: 'key',
      ResourceId: 'mrk-12345678123412341234123456789012',
    }
    const region = 'us-east-1'
    const expectedArn =
      'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012'
    expect(constructArnInOtherRegion(parsedArn, region)).to.equal(expectedArn)
  })
  it('Precondition: Only reconstruct a multi region ARN.', async () => {
    const parsedArn = {
      Partition: 'aws',
      Region: 'us-west-2',
      AccountId: '123456789012',
      ResourceType: 'key',
      ResourceId: '12345678-1234-1234-1234-123456789012',
    }
    const region = 'us-east-1'
    expect(() => constructArnInOtherRegion(parsedArn, region)).to.throw(
      'Cannot attempt to construct an ARN in a new region from an non-MRK ARN.'
    )
  })
})
