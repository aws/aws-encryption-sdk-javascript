// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { AwsKmsMrkAwareSymmetricKeyringClass } from '../src/kms_mrk_keyring'
import {
  NodeAlgorithmSuite,
  Keyring,
  Newable,
} from '@aws-crypto/material-management'

describe('AwsKmsMrkAwareSymmetricKeyring: constructor', () => {
  //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
  //= type=test
  //# On initialization the caller MUST provide:
  it('set properties', () => {
    const client: any = {}
    const keyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const grantTokens = ['grant']

    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const test = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId,
      grantTokens,
    })
    expect(test.client).to.equal(client)
    expect(test.keyId).to.equal(keyId)
    expect(test.grantTokens).to.equal(grantTokens)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.5
    //= type=test
    //# MUST implement the AWS Encryption SDK Keyring interface (../keyring-
    //# interface.md#interface)
    expect((test as Keyring<NodeAlgorithmSuite>) instanceof Keyring).to.equal(
      true
    )
  })

  it('Configured KMS key identifier must be valid.', () => {
    const client: any = {}
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //= type=test
    //# The AWS KMS key identifier MUST NOT be null or empty.
    expect(
      () =>
        new TestAwsKmsMrkAwareSymmetricKeyring({
          client,
          keyId: '',
        })
    ).to.throw('An AWS KMS key identifier is required.')
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //= type=test
    //# The AWS KMS
    //# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
    //# valid-aws-kms-identifier).
    expect(
      () =>
        new TestAwsKmsMrkAwareSymmetricKeyring({
          client,
          keyId: 'Not:an/arn',
        })
    ).to.throw('Malformed arn.')
    expect(
      () =>
        new TestAwsKmsMrkAwareSymmetricKeyring({
          client,
          // @ts-expect-error passing undefined
          keyId: undefined,
        })
    ).to.throw('An AWS KMS key identifier is required.')

    expect(
      () =>
        new TestAwsKmsMrkAwareSymmetricKeyring({
          client,
          // @ts-expect-error passing null
          keyId: null,
        })
    ).to.throw('An AWS KMS key identifier is required.')

    expect(
      () =>
        new TestAwsKmsMrkAwareSymmetricKeyring({
          client,
          // @ts-expect-error passing a number to expect failure
          keyId: 5,
        })
    ).to.throw('An AWS KMS key identifier is required.')

    expect(
      () =>
        new TestAwsKmsMrkAwareSymmetricKeyring({
          client,
          // @ts-expect-error passing an object to expect failure
          keyId: {},
        })
    ).to.throw('An AWS KMS key identifier is required.')
  })

  it('A KMS CMK alias is a valid CMK identifier', () => {
    const client: any = {}
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const test2 = new TestAwsKmsMrkAwareSymmetricKeyring({
      client,
      keyId: 'alias/example-alias',
    })
    expect(test2).to.be.instanceOf(TestAwsKmsMrkAwareSymmetricKeyring)
  })

  it('provide a client', () => {
    class TestAwsKmsMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-keyring.txt#2.6
    //= type=test
    //# The AWS KMS
    //# SDK client MUST NOT be null.
    expect(
      () =>
        new TestAwsKmsMrkAwareSymmetricKeyring({
          // @ts-expect-error testing that I get an error
          client: false,
          keyId: 'alias/example-alias',
        })
    ).to.throw('An AWS SDK client is required')
  })
})
