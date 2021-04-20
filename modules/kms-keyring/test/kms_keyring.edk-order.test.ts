// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { KmsKeyringClass } from '../src/kms_keyring'
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

describe('KmsKeyring: decrypt EDK order', () => {
  describe('with a single configured CMK', () => {
    it('short circuit on the first success', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const { edk } = edkHelper()
      const edks = [...Array(5)].map(() => edk)
      const state = buildProviderState(edks, suite)
      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        keyIds: [edk.providerInfo],
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
      const state = buildProviderState(edks, suite, { failureCount: 1 })

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        keyIds: [edk.providerInfo],
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)
      expect(state.calls).to.equal(2)
    })

    it('only contract KMS for the single configured CMK', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const edks = [...Array(5)].map(edkHelper).map(({ edk }) => edk)
      const state = buildProviderState(edks, suite, { edkSuccessIndex: 4 })
      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        keyIds: edks.slice(-1).map((v) => v.providerInfo),
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)
      expect(state.calls).to.equal(1)
    })
  })

  describe('with multiple configured CMKs', () => {
    it('if no EDKs match any CMKs never call KMS', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const edks = [...Array(5)].map(edkHelper).map(({ edk }) => edk)
      const keyIds = [...Array(5)]
        .map(edkHelper)
        .map(({ edk }) => edk)
        .map((v) => v.providerInfo)

      let calls = 0
      const clientProvider: any = () => {
        calls += 1
      }
      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider,
        keyIds,
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )

      expect(material.hasUnencryptedDataKey).to.equal(false)
      expect(calls).to.equal(0)
    })

    it('short circuit on the first success', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const edks = [...Array(5)].map(edkHelper).map(({ edk }) => edk)
      const state = buildProviderState(edks, suite)
      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        keyIds: edks.map((v) => v.providerInfo),
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

      const edks = [...Array(5)].map(edkHelper).map(({ edk }) => edk)
      const state = buildProviderState(edks, suite, { failureCount: 1 })

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        keyIds: edks.map((v) => v.providerInfo),
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)
      expect(state.calls).to.equal(2)
    })

    it('only contract KMS for a single overlapping CMK', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const edks = [...Array(5)].map(edkHelper).map(({ edk }) => edk)
      const keyIds = [...Array(5)]
        .map(edkHelper)
        .map(({ edk }) => edk)
        .map((v) => v.providerInfo)
        .concat(edks.slice(-1).map((v) => v.providerInfo))

      const state = buildProviderState(edks, suite, { edkSuccessIndex: 4 })
      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        keyIds: keyIds,
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)
      expect(state.calls).to.equal(1)
    })
  })

  describe('with a discovery filter that has 1 account', () => {
    it('fail every KMS call to ensure we make them all', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const info = edkHelper()
      const edks = [...Array(5)].map(() => info.edk)
      const accountIDs = [info.accountId]

      const state = buildProviderState(edks, suite, {
        failureCount: edks.length,
      })
      const discovery = true
      const discoveryFilter = {
        partition: 'aws',
        accountIDs,
      }

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        discovery,
        discoveryFilter,
      })

      await expect(
        testKeyring.onDecrypt(new NodeDecryptionMaterial(suite, context), edks)
      ).to.rejectedWith(
        'Unable to decrypt data key and one or more KMS CMKs had an error'
      )

      expect(state.calls).to.equal(edks.length)
    })

    it('filter the first, fail the second, and still only 1 KMS call', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const info = edkHelper()
      const edks = [edkHelper().edk, info.edk, info.edk, info.edk]
      const accountIDs = [info.accountId]

      const state = buildProviderState(edks, suite, { failureCount: 1 })
      const discovery = true
      const discoveryFilter = {
        partition: 'aws',
        accountIDs,
      }

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        discovery,
        discoveryFilter,
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)
      expect(state.calls).to.equal(2)
    })

    it('filter all out all EDKs results in 0 KMS calls', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const edks = [...Array(5)].map(edkHelper).map(({ edk }) => edk)
      const accountIDs = [edkHelper().accountId]

      const state = buildProviderState(edks, suite, {
        failureCount: edks.length,
      })
      const discovery = true
      const discoveryFilter = {
        partition: 'aws',
        accountIDs,
      }

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        discovery,
        discoveryFilter,
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )

      expect(material.hasUnencryptedDataKey).to.equal(false)
      expect(state.calls).to.equal(0)
    })
  })

  describe('with a discovery filter that has more than 1 account', () => {
    it('with only 1 account match', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const info = edkHelper()
      const edks = [info.edk]
      const accountIDs = [
        edkHelper().accountId,
        edkHelper().accountId,
        edkHelper().accountId,
        info.accountId,
      ]

      const state = buildProviderState(edks, suite)
      const discovery = true
      const discoveryFilter = {
        partition: 'aws',
        accountIDs,
      }

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        discovery,
        discoveryFilter,
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )

      expect(material.hasUnencryptedDataKey).to.equal(true)
      expect(state.calls).to.equal(1)
    })

    it('where none of the account ids match results in not KMS call', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const edks = [edkHelper().edk]
      const accountIDs = [
        edkHelper().accountId,
        edkHelper().accountId,
        edkHelper().accountId,
      ]

      const state = buildProviderState(edks, suite, {
        failureCount: edks.length,
      })
      const discovery = true
      const discoveryFilter = {
        partition: 'aws',
        accountIDs,
      }

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        discovery,
        discoveryFilter,
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )
      expect(material.hasUnencryptedDataKey).to.equal(false)
      expect(state.calls).to.equal(0)
    })

    it('where an account id match but not the partition results in not KMS call', async () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const info = edkHelper()
      const edks = [info.edk]
      const accountIDs = [
        edkHelper().accountId,
        edkHelper().accountId,
        info.accountId,
      ]

      const state = buildProviderState(edks, suite, {
        failureCount: edks.length,
      })
      const discovery = true
      const discoveryFilter = {
        partition: 'NOTaws',
        accountIDs,
      }

      class TestKmsKeyring extends KmsKeyringClass(
        Keyring as Newable<Keyring<NodeAlgorithmSuite>>
      ) {}

      const testKeyring = new TestKmsKeyring({
        clientProvider: state.clientProvider,
        discovery,
        discoveryFilter,
      })

      const material = await testKeyring.onDecrypt(
        new NodeDecryptionMaterial(suite, context),
        edks
      )
      expect(material.hasUnencryptedDataKey).to.equal(false)
      expect(state.calls).to.equal(0)
    })

    describe('filter will reject EDKs for every combination !p,a|p,!a|!p,!a', () => {
      const context = { some: 'context' }
      const suite = new NodeAlgorithmSuite(
        AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
      )

      const noMatchInfo = [
        edkHelper('aws'),
        edkHelper('notAWS'),
        edkHelper('stillNotAws'),
      ]
      const matchInfo = [edkHelper(), edkHelper()]

      const edks = [
        ...noMatchInfo.map(({ edk }) => edk),
        ...matchInfo.map(({ edk }) => edk),
      ]
      const accountIDs = [
        noMatchInfo[1].accountId,
        ...matchInfo.map(({ accountId }) => accountId),
      ]
      const discovery = true
      const discoveryFilter = {
        partition: 'aws',
        accountIDs,
      }
      it('fail all calls and verify count', async () => {
        const state = buildProviderState(edks, suite, {
          failureCount: matchInfo.length,
        })
        class TestKmsKeyring extends KmsKeyringClass(
          Keyring as Newable<Keyring<NodeAlgorithmSuite>>
        ) {}

        const testKeyring = new TestKmsKeyring({
          clientProvider: state.clientProvider,
          discovery,
          discoveryFilter,
        })

        await expect(
          testKeyring.onDecrypt(
            new NodeDecryptionMaterial(suite, context),
            edks
          )
        ).to.rejectedWith(
          'Unable to decrypt data key and one or more KMS CMKs had an error'
        )

        expect(state.calls).to.equal(matchInfo.length)
      })

      it('fail first call verify success of the second', async () => {
        const state = buildProviderState(edks, suite, {
          failureCount: 1,
          edkSuccessIndex: 4,
        })
        class TestKmsKeyring extends KmsKeyringClass(
          Keyring as Newable<Keyring<NodeAlgorithmSuite>>
        ) {}

        const testKeyring = new TestKmsKeyring({
          clientProvider: state.clientProvider,
          discovery,
          discoveryFilter,
        })

        const material = await testKeyring.onDecrypt(
          new NodeDecryptionMaterial(suite, context),
          edks
        )
        expect(material.hasUnencryptedDataKey).to.equal(true)

        expect(state.calls).to.equal(matchInfo.length)
      })
    })
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

function buildProviderState(
  edks: EncryptedDataKey[],
  { keyLengthBytes }: NodeAlgorithmSuite,
  {
    failureCount = 0,
    edkSuccessIndex,
  }: { failureCount?: number; edkSuccessIndex?: number } = {} as any
) {
  const providerState = { clientProvider: clientProvider as any, calls: 0 }

  return providerState

  function clientProvider() {
    return { decrypt }
    async function decrypt({ KeyId }: any) {
      providerState.calls += 1
      const { calls } = providerState
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
}
