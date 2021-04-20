// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { AwsKmsMrkAwareSymmetricKeyringClass } from '../src/kms_mrk_keyring'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  NodeDecryptionMaterial,
  EncryptedDataKey,
  Keyring,
  needs,
  Newable,
} from '@aws-crypto/material-management'
chai.use(chaiAsPromised)
const { expect } = chai

describe('KmsMrkKeyring: decrypt EDK order', () => {
  it('short circuit on the first success', async () => {
    const context = { some: 'context' }
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )

    const { edk } = edkHelper()
    const edks = [...Array(5)].map(() => edk)
    const state = buildClientState(edks, suite)
    class TestKmsMrkKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsMrkKeyring({
      client: state.client,
      keyId: edk.providerInfo,
    })

    const material = await testKeyring.onDecrypt(
      new NodeDecryptionMaterial(suite, context),
      edks
    )

    expect(material.hasUnencryptedDataKey).to.equal(true)
    expect(state.calls).to.equal(1)
  })

  it('errors should not halt, but also short circuit after success', async () => {
    const context = { some: 'context' }
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )

    const { edk } = edkHelper()
    const edks = [...Array(5)].map(() => edk)
    const state = buildClientState(edks, suite, { failureCount: 1 })

    class TestKmsMrkKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsMrkKeyring({
      client: state.client,
      keyId: edk.providerInfo,
    })

    const material = await testKeyring.onDecrypt(
      new NodeDecryptionMaterial(suite, context),
      edks
    )

    expect(material.hasUnencryptedDataKey).to.equal(true)
    expect(state.calls).to.equal(2)
  })

  it('only contact KMS for the single configured CMK', async () => {
    const context = { some: 'context' }
    const suite = new NodeAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
    )

    const edks = [...Array(5)].map(edkHelper).map(({ edk }) => edk)
    const state = buildClientState(edks, suite, { edkSuccessIndex: 4 })
    class TestKmsMrkKeyring extends AwsKmsMrkAwareSymmetricKeyringClass(
      Keyring as Newable<Keyring<NodeAlgorithmSuite>>
    ) {}

    const testKeyring = new TestKmsMrkKeyring({
      client: state.client,
      keyId: edks[edks.length - 1].providerInfo,
    })

    const material = await testKeyring.onDecrypt(
      new NodeDecryptionMaterial(suite, context),
      edks
    )

    expect(material.hasUnencryptedDataKey).to.equal(true)
    expect(state.calls).to.equal(1)
  })
})

function edkHelper(partition?: any) {
  // Very dirty uuid "thing"
  const keyId = [...Array(3)]
    .map(() => Math.random().toString(16).slice(2))
    .join('')
  const accountId = Math.random().toString().slice(2, 14)
  const edk = new EncryptedDataKey({
    providerId: 'aws-kms',
    providerInfo: `arn:${
      typeof partition === 'string' ? partition : 'aws'
    }:kms:us-east-1:${accountId}:key/${keyId}`,
    encryptedDataKey: Buffer.alloc(5),
  })

  return {
    keyId,
    accountId,
    edk,
  }
}

function buildClientState(
  edks: EncryptedDataKey[],
  { keyLengthBytes }: NodeAlgorithmSuite,
  {
    failureCount = 0,
    edkSuccessIndex,
  }: { failureCount?: number; edkSuccessIndex?: number } = {} as any
) {
  const clientState = { client: { decrypt } as any, calls: 0 }

  return clientState

  async function decrypt({ KeyId }: any) {
    clientState.calls += 1
    const { calls } = clientState
    // If I need to fail some of the filtered elements
    needs(calls > failureCount, 'try again')
    /* It may be that the list of EDKs will be flittered.
     * in which case the success EDK
     * the call count will not
     * match the index of the intended EDK.
     * In which case just use the one provided...
     */
    expect(KeyId).to.equal(edks[edkSuccessIndex || calls - 1].providerInfo)
    return {
      Plaintext: new Uint8Array(keyLengthBytes),
      KeyId,
    }
  }
}
