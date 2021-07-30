// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
  NodeAlgorithmSuite,
  NodeEncryptionMaterial,
  Keyring,
  AlgorithmSuiteIdentifier,
  Newable,
} from '@aws-crypto/material-management'
import { AwsKmsMrkAwareSymmetricDiscoveryKeyringClass } from '../src/kms_mrk_discovery_keyring'
chai.use(chaiAsPromised)
const { expect } = chai

describe('AwsKmsMrkAwareSymmetricKeyring: _onEncrypt', () => {
  it('Encrypt returns an error.', async () => {
    const client: any = { config: { region: 'us-west-2' } }
    const discoveryFilter = { accountIDs: ['123456789012'], partition: 'aws' }
    const context = { some: 'context' }
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )

    class TestKmsMrkKeyring extends AwsKmsMrkAwareSymmetricDiscoveryKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsMrkKeyring({
      client,
      discoveryFilter,
    })

    //= compliance/framework/aws-kms/aws-kms-mrk-aware-symmetric-region-discovery-keyring.txt#2.7
    //= type=test
    //# This function MUST fail.
    return expect(
      testKeyring.onEncrypt(new NodeEncryptionMaterial(suite, context))
    ).to.rejectedWith(
      Error,
      'AwsKmsMrkAwareSymmetricDiscoveryKeyring cannot be used to encrypt'
    )
  })
})
