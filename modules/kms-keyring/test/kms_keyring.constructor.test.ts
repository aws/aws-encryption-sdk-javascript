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

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import {
  KmsKeyringClass,
  KeyRingConstructible // eslint-disable-line no-unused-vars
} from '../src/kms_keyring'
import { NodeAlgorithmSuite, Keyring } from '@aws-crypto/material-management' // eslint-disable-line no-unused-vars

describe('KmsKeyring: constructor', () => {
  it('set properties', () => {
    const clientProvider: any = () => {}
    const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const keyIds = ['arn:aws:kms:us-east-1:123456789012:alias/example-alias']
    const grantTokens = ['grant']

    class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

    const test = new TestKmsKeyring({ clientProvider, generatorKeyId, keyIds, grantTokens })
    expect(test.clientProvider).to.equal(clientProvider)
    expect(test.generatorKeyId).to.equal(generatorKeyId)
    expect(test.keyIds).to.deep.equal(keyIds)
    expect(test.grantTokens).to.equal(grantTokens)
    expect(test.isDiscovery).to.equal(false)
  })

  it('set properties for discovery keyring', () => {
    const clientProvider: any = () => {}
    const discovery = true

    class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

    const test = new TestKmsKeyring({ clientProvider, discovery })
    expect(test.clientProvider).to.equal(clientProvider)
    expect(test.generatorKeyId).to.equal(undefined)
    expect(test.keyIds).to.deep.equal([])
    expect(test.grantTokens).to.equal(undefined)
    expect(test.isDiscovery).to.equal(true)
  })

  it('Precondition: A noop KmsKeyring is not allowed.', () => {
    class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}
    const clientProvider: any = () => {}
    expect(() => new TestKmsKeyring({ clientProvider })).to.throw()
  })

  it('Precondition: A keyring can be either a Discovery or have keyIds configured.', () => {
    class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}
    const clientProvider: any = () => {}
    const generatorKeyId = 'arn:aws:kms:us-east-1:123456789012:alias/example-alias'
    const keyIds = ['arn:aws:kms:us-east-1:123456789012:alias/example-alias']
    const discovery = true
    expect(() => new TestKmsKeyring({ clientProvider, generatorKeyId, keyIds, discovery })).to.throw()
  })

  it('Precondition: All KMS key arns must be valid.', () => {
    const clientProvider: any = () => {}
    class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}

    expect(() => new TestKmsKeyring({
      clientProvider,
      generatorKeyId: 'Not arn'
    })).to.throw()

    expect(() => new TestKmsKeyring({
      clientProvider,
      keyIds: ['Not arn']
    })).to.throw()

    expect(() => new TestKmsKeyring({
      clientProvider,
      keyIds: ['arn:aws:kms:us-east-1:123456789012:alias/example-alias', 'Not arn']
    })).to.throw()
  })

  it('Precondition: clientProvider needs to be a callable function.', () => {
    class TestKmsKeyring extends KmsKeyringClass(Keyring as KeyRingConstructible<NodeAlgorithmSuite>) {}
    const clientProvider: any = 'not function'
    const discovery = true
    expect(() => new TestKmsKeyring({ clientProvider, discovery })).to.throw()
  })
})
