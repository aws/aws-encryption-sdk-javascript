// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { getAwsKmsMrkAwareStrictMultiKeyringBuilder } from '../src/kms_mrk_strict_multi_keyring'
import { AwsKmsMrkAwareSymmetricKeyringClass } from '../src/kms_mrk_keyring'
import {
  MultiKeyringNode,
  Newable,
  KeyringNode,
} from '@aws-crypto/material-management'

describe('buildAwsKmsMrkAwareStrictMultiKeyringNode', () => {
  class TestMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
    KeyringNode as Newable<KeyringNode>
  ) {}

  const testBuilder = getAwsKmsMrkAwareStrictMultiKeyringBuilder(
    TestMrkAwareSymmetricKeyring,
    MultiKeyringNode,
    (): any => {}
  )

  it('constructs expected child/generator keyrings', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
    const keyArn =
      'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f'
    const keyIds = [keyArn]
    const grantTokens = ['grant', 'tokens']

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# The caller MUST provide:
    const test = testBuilder({
      generatorKeyId,
      keyIds,
      clientProvider(region: string): any {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
        //= type=test
        //# *  The AWS KMS client that MUST be created by the regional client
        //# supplier when called with the region part of the generator ARN or
        //# a signal for the AWS SDK to select the default region.
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
        //= type=test
        //# *  The AWS KMS client that MUST be created by the regional client
        //# supplier when called with the region part of the AWS KMS key
        //# identifier or a signal for the AWS SDK to select the default
        //# region.
        expect(region).to.equal('us-west-2')
        return { config: { region } }
      },
      grantTokens,
    })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
    //# by using this generator keyring as the generator keyring (../multi-
    //# keyring.md#generator-keyring) and this set of child keyrings as the
    //# child keyrings (../multi-keyring.md#child-keyrings).
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# This Multi-
    //# Keyring MUST be this functions output.
    expect(test instanceof MultiKeyringNode).to.equal(true)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# If there is a generator input then the generator keyring MUST be a
    //# AWS KMS MRK Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-
    //# keyring.md) initialized with
    expect(test.generator instanceof TestMrkAwareSymmetricKeyring).to.equal(
      true
    )
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
    //= type=test
    //# If there is a set of child identifiers then a set of AWS KMS MRK
    //# Aware Symmetric Keyring (aws-kms-mrk-aware-symmetric-keyring.md) MUST
    //# be created for each AWS KMS key identifier by initialized each
    //# keyring with
    expect(test.children).to.have.lengthOf(1)
    expect(test.children[0] instanceof TestMrkAwareSymmetricKeyring).to.equal(
      true
    )

    const generator = test.generator as TestMrkAwareSymmetricKeyring
    const child = test.children[0] as TestMrkAwareSymmetricKeyring
    expect(!!generator.client).to.equal(true)
    expect(!!child.client).to.equal(true)
    // @ts-expect-error checking a private value
    expect(generator.client.config.region).to.equal('us-west-2')
    // @ts-expect-error checking a private value
    expect(child.client.config.region).to.equal('us-west-2')
    expect(generator.grantTokens).to.deep.equal(grantTokens)
    expect(child.grantTokens).to.deep.equal(grantTokens)
  })

  it('returns instance of MultiKeyringNode', () => {
    const generatorKeyId =
      'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
    const test = testBuilder({ generatorKeyId, clientProvider: () => true })
    expect(test instanceof MultiKeyringNode).to.equal(true)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
  //= type=test
  //# At least one non-null or non-empty string AWS
  //# KMS key identifiers exists in the input this function MUST fail.
  it('At least one non-null or non-empty string AWS KMS key identifiers exists in the input or this function MUST fail.', async () => {
    const expectedErrorMessage =
      'Noop keyring is not allowed: Set a generatorKeyId or at least one keyId.'
    // @ts-expect-error The function has required arguments
    expect(() => testBuilder()).to.throw(Error, expectedErrorMessage)
    expect(() => testBuilder({})).to.throw(Error, expectedErrorMessage)
    expect(() => testBuilder({ keyIds: [] })).to.throw(
      Error,
      expectedErrorMessage
    )
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
  //= type=test
  //# If any of the AWS KMS key identifiers is null or an empty string this
  //# function MUST fail.
  it('If any of the AWS KMS key identifiers is null or an empty string this function MUST fail.', async () => {
    const expectedErrorMessage =
      'Noop keyring is not allowed: Set a generatorKeyId or at least one keyId.'
    const validKeyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    expect(() =>
      testBuilder({
        generatorKeyId: validKeyId,
        keyIds: [''],
      })
    ).to.throw(Error, expectedErrorMessage)
    expect(() =>
      testBuilder({
        generatorKeyId: validKeyId,
        keyIds: [validKeyId, ''],
      })
    ).to.throw(Error, expectedErrorMessage)
    expect(() =>
      testBuilder({
        generatorKeyId: validKeyId,
        // @ts-expect-error undefined is not a string
        keyIds: [undefined],
      })
    ).to.throw(Error, expectedErrorMessage)
    expect(() =>
      testBuilder({
        generatorKeyId: validKeyId,
        // @ts-expect-error undefined is not a string
        keyIds: [validKeyId, undefined],
      })
    ).to.throw(Error, expectedErrorMessage)
    expect(() =>
      testBuilder({
        generatorKeyId: validKeyId,
        // @ts-expect-error null is not a string
        keyIds: [null],
      })
    ).to.throw(Error, expectedErrorMessage)
    expect(() =>
      testBuilder({
        generatorKeyId: validKeyId,
        // @ts-expect-error null is not a string
        keyIds: [validKeyId, null],
      })
    ).to.throw(Error, expectedErrorMessage)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
  //= type=test
  //# All
  //# AWS KMS identifiers are passed to Assert AWS KMS MRK are unique (aws-
  //# kms-mrk-are-unique.md#Implementation) and the function MUST return
  //# success otherwise this MUST fail.
  it('related multi-region keys are not allowed.', async () => {
    expect(() =>
      testBuilder({
        generatorKeyId:
          'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
        keyIds: ['mrk-12345678123412341234123456789012'],
      })
    ).to.throw(Error, 'Related multi-Region keys:')

    expect(() =>
      testBuilder({
        keyIds: [
          'mrk-12345678123412341234123456789012',
          'arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012',
        ],
      })
    ).to.throw(Error, 'Related multi-Region keys:')
  })

  it('Postcondition: If the configured clientProvider is not able to create a client for a defined generator key, throw an error.', async () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:2222222222222:key/mrk-4321abcd12ab34cd56ef1234567890ab'
    const clientProvider: any = () => {
      return false
    }
    expect(() =>
      testBuilder({
        clientProvider,
        generatorKeyId,
      })
    ).to.throw(
      Error,
      'Configured clientProvider is unable to create a client for configured'
    )
  })

  it('Create an AWS KMS client with a default region.', async () => {
    const generatorKeyId = 'alias/my-alias'
    const testBuilder = getAwsKmsMrkAwareStrictMultiKeyringBuilder(
      TestMrkAwareSymmetricKeyring,
      MultiKeyringNode,
      (region: string): any => {
        // This is tested, because this is being passed to the builder.
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
        //= type=test
        //# If
        //# a regional client supplier is not passed, then a default MUST be
        //# created that takes a region string and generates a default AWS SDK
        //# client for the given region.
        //
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.6
        //= type=test
        //# NOTE: The AWS Encryption SDK SHOULD NOT attempt to evaluate its own
        //# default region.
        expect(region).to.equal('')
        return {}
      }
    )

    testBuilder({
      generatorKeyId,
    })
  })
})
