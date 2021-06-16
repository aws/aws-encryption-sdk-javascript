// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { AwsKmsMrkAwareSymmetricDiscoveryKeyringClass } from '../src/kms_mrk_discovery_keyring'
import {
  NodeAlgorithmSuite,
  Keyring,
  Newable,
} from '@aws-crypto/material-management'

describe('AwsKmsMrkAwareSymmetricDiscoveryKeyring: constructor', () => {
  it('set properties', () => {
    const client: any = { config: { region: 'us-west-2' } }
    const grantTokens = ['grant']
    const discoveryFilter = { accountIDs: ['123456789012'], partition: 'aws' }

    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //= type=test
    //# On initialization the caller MUST provide:
    const test = new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
      client,
      discoveryFilter,
      grantTokens,
    })
    expect(test.client).to.equal(client)
    expect(test.grantTokens).to.equal(grantTokens)

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.5
    //= type=test
    //# MUST implement that AWS Encryption SDK Keyring interface (../keyring-
    //# interface.md#interface)
    expect((test as Keyring<NodeAlgorithmSuite>) instanceof Keyring).to.equal(
      true
    )
  })

  it('The keyring MUST know what Region the AWS KMS client is in', () => {
    const client: any = { config: {} }
    const discoveryFilter = { accountIDs: ['123456789012'], partition: 'aws' }

    class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //= type=test
    //# The keyring MUST know what Region the AWS KMS client is in.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //= type=test
    //# It
    //# SHOULD obtain this information directly from the client as opposed to
    //# having an additional parameter.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //= type=test
    //# However if it can not, then it MUST
    //# NOT create the client itself.
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.6
    //= type=test
    //# It SHOULD have a Region parameter and
    //# SHOULD try to identify mismatched configurations.
    expect(
      () =>
        new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
          client,
          discoveryFilter,
        })
    ).to.throw('Client must be configured to a region')
  })

  it('Precondition: The AwsKmsMrkAwareSymmetricDiscoveryKeyring Discovery filter *must* be able to match something.', () => {
    testAccountAndPartition([], undefined)
    testAccountAndPartition([''], undefined)
    testAccountAndPartition(undefined, '')
    testAccountAndPartition(['', '123456789012'], 'aws')
    testAccountAndPartition(['123456789012'], '')
    testAccountAndPartition([''], 'aws')
    testAccountAndPartition([], 'aws')

    function testAccountAndPartition(accountIDs: any, partition: any) {
      const client: any = { config: { region: 'us-west-2' } }

      class TestAwsKmsMrkAwareSymmetricDiscoveryKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}
      expect(
        () =>
          new TestAwsKmsMrkAwareSymmetricDiscoveryKeyring({
            client,
            discoveryFilter: { accountIDs, partition } as any,
          })
      ).to.throw('A discovery filter must be able to match something.')
    }
  })
})
