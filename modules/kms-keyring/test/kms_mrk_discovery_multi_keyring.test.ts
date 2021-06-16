// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { getAwsKmsMrkAwareDiscoveryMultiKeyringBuilder } from '../src/kms_mrk_discovery_multi_keyring'
import { AwsKmsMrkAwareSymmetricDiscoveryKeyringClass } from '../src/kms_mrk_discovery_keyring'
import {
  MultiKeyringNode,
  Newable,
  KeyringNode,
} from '@aws-crypto/material-management'

describe('buildAwsKmsMrkAwareStrictMultiKeyringNode', () => {
  class TestMrkAwareSymmetricKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
    KeyringNode as Newable<KeyringNode>
  ) {}

  const testBuilder = getAwsKmsMrkAwareDiscoveryMultiKeyringBuilder(
    TestMrkAwareSymmetricKeyring,
    MultiKeyringNode,
    (region: string): any => {
      return { config: { region } }
    }
  )
  it('constructs expected child/generator keyrings', async () => {
    const regions = ['us-west-2', 'us-east-1']
    const discoveryFilter = { partition: 'aws', accountIDs: ['1234'] }
    const grantTokens = ['grant', 'tokens']

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# The caller MUST provide:
    const test = testBuilder({
      discoveryFilter,
      regions,
      clientProvider(region: string): any {
        //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
        //= type=test
        //# A set of AWS KMS clients MUST be created by calling regional client
        //# supplier for each region in the input set of regions.
        expect(region.includes(region)).to.equal(true)
        return { config: { region } }
      },
      grantTokens,
    })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# Then a Multi-Keyring (../multi-keyring.md#inputs) MUST be initialize
    //# by using this set of discovery keyrings as the child keyrings
    //# (../multi-keyring.md#child-keyrings).
    //
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# This Multi-Keyring MUST be
    //# this functions output.
    expect(test instanceof MultiKeyringNode).to.equal(true)

    expect(!!test.generator).to.equal(false)
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# Then a set of AWS KMS MRK Aware Symmetric Region Discovery Keyring
    //# (aws-kms-mrk-aware-symmetric-region-discovery-keyring.md) MUST be
    //# created for each AWS KMS client by initializing each keyring with
    expect(test.children).to.have.lengthOf(2)
    expect(test.children[0] instanceof TestMrkAwareSymmetricKeyring).to.equal(
      true
    )
    expect(test.children[1] instanceof TestMrkAwareSymmetricKeyring).to.equal(
      true
    )
    const child1 = test.children[0] as TestMrkAwareSymmetricKeyring
    const child2 = test.children[1] as TestMrkAwareSymmetricKeyring
    expect(!!child1.client).to.equal(true)
    expect(!!child2.client).to.equal(true)
    expect(
      // @ts-ignore the V3 client has set the config to protected
      child1.client.config.region
    ).to.equal('us-west-2')
    expect(
      // @ts-ignore the V3 client has set the config to protected
      child2.client.config.region
    ).to.equal('us-east-1')

    expect(child1.discoveryFilter).to.deep.equal(discoveryFilter)
    expect(child2.discoveryFilter).to.deep.equal(discoveryFilter)
    expect(child1.grantTokens).to.deep.equal(grantTokens)
    expect(child2.grantTokens).to.deep.equal(grantTokens)
  })

  //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
  //= type=test
  //# If a regional client supplier is not passed,
  //# then a default MUST be created that takes a region string and
  //# generates a default AWS SDK client for the given region.
  it('Can create clients from the default provider.', () => {
    const regions = ['us-west-2', 'us-east-1']
    const test = testBuilder({ regions })
    expect(test instanceof MultiKeyringNode).to.equal(true)
    expect(
      // @ts-ignore the V3 client has set the config to protected
      test.children[0].client.config.region
    ).to.equal('us-west-2')
    expect(
      // @ts-ignore the V3 client has set the config to protected
      test.children[1].client.config.region
    ).to.equal('us-east-1')
  })

  it('If an empty set of Region is provided this function MUST fail.', async () => {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# If an empty set of Region is provided this function MUST fail.
    expect(() => testBuilder({ regions: [] })).to.throw(
      Error,
      'Configured regions must contain at least one region.'
    )
  })

  it('If any element of the set of regions is null or an empty string this function MUST fail.', async () => {
    //= compliance/framework/aws-kms/aws-kms-mrk-aware-multi-keyrings.txt#2.5
    //= type=test
    //# If
    //# any element of the set of regions is null or an empty string this
    //# function MUST fail.
    expect(() =>
      testBuilder({
        regions: ['us-west-2', ''],
      })
    ).to.throw(
      Error,
      'Configured regions must not contain a null or empty string as a region.'
    )
    expect(() =>
      testBuilder({
        // @ts-expect-error undefined is not a string
        regions: ['us-west-2', undefined],
      })
    ).to.throw(
      Error,
      'Configured regions must not contain a null or empty string as a region.'
    )
  })

  it('Postcondition: If the configured clientProvider is not able to create a client for a defined region, throw an error.', async () => {
    const regions = ['us-west-2', 'us-east-1']
    const clientProvider: any = () => {
      return false
    }
    expect(() => testBuilder({ clientProvider, regions })).to.throw(
      Error,
      'Configured clientProvider is unable to create a client for a configured region.'
    )
  })
})
