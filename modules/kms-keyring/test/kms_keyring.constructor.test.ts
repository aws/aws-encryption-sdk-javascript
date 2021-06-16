// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { KmsKeyringClass } from '../src/kms_keyring'
import {
  NodeAlgorithmSuite,
  Keyring,
  Newable,
} from '@aws-crypto/material-management'

describe('KmsKeyring: constructor', () => {
  it('set properties', () => {
    const clientProvider: any = () => {}
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const keyIds = ['arn:aws:kms:us-east-1:123456789012:alias/example-alias']
    const grantTokens = ['grant']

    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const test = new TestKmsKeyring({
      clientProvider,
      generatorKeyId,
      keyIds,
      grantTokens,
    })
    expect(test.clientProvider).to.equal(clientProvider)
    expect(test.generatorKeyId).to.equal(generatorKeyId)
    expect(test.keyIds).to.deep.equal(keyIds)
    expect(test.grantTokens).to.equal(grantTokens)
    expect(test.isDiscovery).to.equal(false)
  })

  it('set properties for discovery keyring', () => {
    const clientProvider: any = () => {}
    const discovery = true
    const discoveryFilter = { accountIDs: ['123456789012'], partition: 'aws' }

    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const test = new TestKmsKeyring({
      clientProvider,
      discovery,
      discoveryFilter,
    })
    expect(test.clientProvider).to.equal(clientProvider)
    expect(test.generatorKeyId).to.equal(undefined)
    expect(test.keyIds).to.deep.equal([])
    expect(test.grantTokens).to.equal(undefined)
    expect(test.isDiscovery).to.equal(true)
    expect(test.discoveryFilter).to.deep.equal(discoveryFilter)
  })

  it('Precondition: This is an abstract class. (But TypeScript does not have a clean way to model this)', () => {
    const clientProvider: any = () => {}
    const KmsKeyring = KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    )
    expect(() => new KmsKeyring({ clientProvider })).to.throw(
      'new KmsKeyring is not allowed'
    )
  })

  it('Precondition: A noop KmsKeyring is not allowed.', () => {
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}
    const clientProvider: any = () => {}
    expect(() => new TestKmsKeyring({ clientProvider })).to.throw()
  })

  it('Precondition: A keyring can be either a Discovery or have keyIds configured.', () => {
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}
    const clientProvider: any = () => {}
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const keyIds = ['arn:aws:kms:us-east-1:123456789012:alias/example-alias']
    const discovery = true
    expect(
      () =>
        new TestKmsKeyring({
          clientProvider,
          generatorKeyId,
          keyIds,
          discovery,
        })
    ).to.throw()
  })

  it('Precondition: Discovery filter can only be configured in discovery mode.', () => {
    const generatorKeyId =
      'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const keyIds = ['arn:aws:kms:us-east-1:123456789012:alias/example-alias']

    testDiscoveryWithCMKs(
      { partition: 'aws', accountIDs: ['123456789012'] },
      generatorKeyId,
      undefined
    )
    testDiscoveryWithCMKs({}, generatorKeyId, undefined)
    testDiscoveryWithCMKs(
      { partition: 'aws', accountIDs: ['123456789012'] },
      undefined,
      keyIds
    )
    testDiscoveryWithCMKs({}, undefined, keyIds)
    testDiscoveryWithCMKs(
      { partition: 'aws', accountIDs: ['123456789012'] },
      generatorKeyId,
      keyIds
    )
    testDiscoveryWithCMKs({}, generatorKeyId, keyIds)

    function testDiscoveryWithCMKs(
      discoveryFilter: any,
      generatorKeyId: any,
      keyIds: any
    ) {
      const clientProvider: any = () => {}

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}
      expect(
        () =>
          new TestKmsKeyring({
            clientProvider,
            generatorKeyId,
            keyIds,
            discoveryFilter,
          })
      ).to.throw(
        'Account and partition decrypt filtering are only supported when discovery === true'
      )
    }
  })

  it('Precondition: A Discovery filter *must* be able to match something.', () => {
    testAccountAndPartition([], undefined)
    testAccountAndPartition([''], undefined)
    testAccountAndPartition(undefined, '')
    testAccountAndPartition(['', '123456789012'], 'aws')
    testAccountAndPartition(['123456789012'], '')
    testAccountAndPartition([''], 'aws')
    testAccountAndPartition([], 'aws')

    function testAccountAndPartition(accountIDs: any, partition: any) {
      const clientProvider: any = () => {}
      const discovery = true

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}
      expect(
        () =>
          new TestKmsKeyring({
            clientProvider,
            discovery,
            discoveryFilter: { accountIDs, partition } as any,
          })
      ).to.throw('A discovery filter must be able to match something.')
    }
  })

  it('Precondition: All KMS key identifiers must be valid.', () => {
    const clientProvider: any = () => {}
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    expect(
      () =>
        new TestKmsKeyring({
          clientProvider,
          generatorKeyId: 'Not:an/arn',
        })
    ).to.throw()

    expect(
      () =>
        new TestKmsKeyring({
          clientProvider,
          keyIds: ['Not:an/arn'],
        })
    ).to.throw()

    expect(
      () =>
        new TestKmsKeyring({
          clientProvider,
          keyIds: [
            'arn:aws:kms:us-east-1:123456789012:alias/example-alias',
            'Not:an/arn',
          ],
        })
    ).to.throw()

    expect(
      () =>
        new TestKmsKeyring({
          clientProvider,
          generatorKeyId: '',
        })
    ).to.throw()

    expect(
      () =>
        new TestKmsKeyring({
          clientProvider,
          keyIds: [''],
        })
    ).to.throw()
  })

  it('An KMS CMK alias is a valid CMK identifier', () => {
    const clientProvider: any = () => {}
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const test = new TestKmsKeyring({
      clientProvider,
      generatorKeyId: 'alias/example-alias',
      keyIds: ['alias/example-alias'],
    })
    expect(test).to.be.instanceOf(TestKmsKeyring)
  })

  it('Precondition: clientProvider needs to be a callable function.', () => {
    class TestKmsKeyring extends KmsKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}
    const clientProvider: any = 'not function'
    const discovery = true
    expect(() => new TestKmsKeyring({ clientProvider, discovery })).to.throw()
  })
})
