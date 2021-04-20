// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { awsKmsMrkAreUnique } from '../src/aws_kms_mrk_are_unique'

describe('awsKmsMrkAreUnique', () => {
  //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
  //= type=test
  //# The caller MUST provide:
  it('basic usage', () => {
    expect(() =>
      awsKmsMrkAreUnique([
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
      ])
    ).to.not.throw()
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
  //= type=test
  //# If the list does not contain any multi-Region keys (aws-kms-key-
  //# arn.md#identifying-an-aws-kms-multi-region-key) this function MUST
  //# exit successfully.
  it('only multi-Region keys are an error', () => {
    expect(() =>
      awsKmsMrkAreUnique([
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
      ])
    ).to.not.throw()
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
  //= type=test
  //# If there are zero duplicate resource ids between the multi-region
  //# keys, this function MUST exit successfully
  it('multi-region keys that do not duplicate ', () => {
    expect(() =>
      awsKmsMrkAreUnique([
        'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
        'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7',
      ])
    ).to.not.throw()
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-are-unique.txt#2.5
  //= type=test
  //# If any duplicate multi-region resource ids exist, this function MUST
  //# yield an error that includes all identifiers with duplicate resource
  //# ids not only the first duplicate found.
  describe('related multi-region keys are not allowed.', () => {
    it('related multi-Region keys error', () => {
      const relatedKeys = [
        'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
        'arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123412341234123456789012',
      ]
      expect(() => awsKmsMrkAreUnique(relatedKeys)).to.throw(
        'Related multi-Region keys:'
      )
    })

    it('error contains the related keys', () => {
      const relatedKeys = [
        'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
        'arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123412341234123456789012',
      ]
      const keys = [
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
      ]
      expect(() => awsKmsMrkAreUnique(keys.concat(relatedKeys))).to.throw(
        relatedKeys.join(',')
      )
    })

    it('error even for raw key id', () => {
      const relatedKeys = [
        'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
        'mrk-12345678123412341234123456789012',
      ]
      const keys = [
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
      ]
      expect(() => awsKmsMrkAreUnique(keys.concat(relatedKeys))).to.throw(
        relatedKeys.join(',')
      )
    })

    it('Postcondition: Remove non-duplicate multi-Region keys. ', () => {
      const relatedKeys = [
        'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
        'mrk-12345678123412341234123456789012',
      ]
      const keys = [
        'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7',
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
      ]
      expect(() => awsKmsMrkAreUnique(keys.concat(relatedKeys))).to.throw(
        relatedKeys.join(',')
      )
    })

    it('show all duplicates', () => {
      const relatedKeys = [
        'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
        'mrk-12345678123412341234123456789012',
        'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7',
        'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7',
      ]
      const keys = [
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
        'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
        'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
        'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
        'alias/my-alias',
      ]
      expect(() => awsKmsMrkAreUnique(keys.concat(relatedKeys))).to.throw(
        relatedKeys.join(',')
      )
    })
  })
})
