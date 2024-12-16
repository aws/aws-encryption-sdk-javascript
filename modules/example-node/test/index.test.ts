// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import chai, { expect } from 'chai'
import { rsaTest } from '../src/rsa_simple'
import { kmsSimpleTest } from '../src/kms_simple'
import { kmsStreamTest } from '../src/kms_stream'
import { aesTest } from '../src/aes_simple'
import { multiKeyringTest } from '../src/multi_keyring'
import { cachingCMMNodeSimpleTest } from '../src/caching_cmm'
import { disableCommitmentTest } from '../src/disable_commitment'
import {
  kmsEncryptWithMaxEncryptedDataKeysTest,
  kmsDecryptWithMaxEncryptedDataKeysTest,
} from '../src/kms_max_encrypted_data_keys'
import { kmsMultiRegionSimpleTest } from '../src/kms_multi_region_simple'
import { kmsMultiRegionDiscoveryTest } from '../src/kms_multi_region_discovery'
import { readFileSync } from 'fs'
import { hKeyringSimpleTest } from '../src/kms-hierarchical-keyring/simple'
import { hKeyringMultiTenancy } from '../src/kms-hierarchical-keyring/multi_tenancy'
import { hKeyringCachingCMMNodeSimpleTest } from '../src/kms-hierarchical-keyring/caching_cmm'
import chaiAsPromised from 'chai-as-promised'
import { hKeyringDisableCommitmentTest } from '../src/kms-hierarchical-keyring/disable_commitment'
import { hKeyringStreamTest } from '../src/kms-hierarchical-keyring/stream'
import { hierarchicalAesMultiKeyringTest } from '../src/kms-hierarchical-keyring/multi_keyring'

chai.use(chaiAsPromised)
describe('test', () => {
  describe('AWS KMS Hierarchical Keyring', () => {
    it('Simple', async () => {
      const { cleartext, plaintext } = await hKeyringSimpleTest()

      expect(plaintext.toString()).to.equal(cleartext)
    })

    it('Multi-tenancy', async () => {
      const { decryptsFailed, cleartext, plaintextA, plaintextB } =
        await hKeyringMultiTenancy()

      expect(decryptsFailed).to.be.true
      expect(plaintextA.toString()).to.equal(cleartext)
      expect(plaintextB.toString()).to.equal(cleartext)
    })

    it('Caching CMM node', async () => {
      const { cleartext, plaintext } = await hKeyringCachingCMMNodeSimpleTest()

      expect(plaintext.toString()).to.equal(cleartext)
    })

    it('disableCommitmentTest', async () => {
      const { cleartext, plaintext } = await hKeyringDisableCommitmentTest()

      expect(plaintext.toString()).to.equal(cleartext)
    })

    it('Stream', async () => {
      const test = await hKeyringStreamTest(__filename)
      const clearFile = readFileSync(__filename)

      expect(test).to.deep.equal(clearFile)
    })

    it('Multi Keyring', async () => {
      const { cleartext, plaintext } = await hierarchicalAesMultiKeyringTest()

      expect(plaintext.toString()).to.equal(cleartext)
    })
  })

  it('rsa', async () => {
    const { cleartext, plaintext } = await rsaTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kms simple', async () => {
    const { cleartext, plaintext } = await kmsSimpleTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kms stream', async () => {
    const test = await kmsStreamTest(__filename)
    const clearFile = readFileSync(__filename)

    expect(test).to.deep.equal(clearFile)
  })

  it('aes', async () => {
    const { cleartext, plaintext } = await aesTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('multi keyring', async () => {
    const { cleartext, plaintext } = await multiKeyringTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('caching CMM node', async () => {
    const { cleartext, plaintext } = await cachingCMMNodeSimpleTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('disableCommitmentTest', async () => {
    const { cleartext, plaintext } = await disableCommitmentTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kmsEncryptWithMaxEncryptedDataKeysTest, less than max', async () => {
    const { cleartext, plaintext } =
      await kmsEncryptWithMaxEncryptedDataKeysTest(2)
    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kmsEncryptWithMaxEncryptedDataKeysTest, equal to max', async () => {
    const { cleartext, plaintext } =
      await kmsEncryptWithMaxEncryptedDataKeysTest(3)
    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kmsEncryptWithMaxEncryptedDataKeysTest, more than max', async () => {
    await expect(kmsEncryptWithMaxEncryptedDataKeysTest(4)).to.rejectedWith(
      Error,
      'maxEncryptedDataKeys exceeded.'
    )
  })

  it('kmsDecryptWithMaxEncryptedDataKeysTest, less than max', async () => {
    const { cleartext, plaintext } =
      await kmsDecryptWithMaxEncryptedDataKeysTest(2)
    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kmsDecryptWithMaxEncryptedDataKeysTest, equal to max', async () => {
    const { cleartext, plaintext } =
      await kmsDecryptWithMaxEncryptedDataKeysTest(3)
    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kmsDecryptWithMaxEncryptedDataKeysTest, more than max', async () => {
    await expect(kmsDecryptWithMaxEncryptedDataKeysTest(4)).to.rejectedWith(
      Error,
      'maxEncryptedDataKeys exceeded.'
    )
  })

  it('kms multi-Region simple', async () => {
    const { cleartext, plaintext } = await kmsMultiRegionSimpleTest()

    expect(plaintext.toString()).to.equal(cleartext)
  })

  it('kms multi-Region discovery', async function () {
    this.timeout(3000)
    const { result, cleartext } = await kmsMultiRegionSimpleTest()

    const { plaintext } = await kmsMultiRegionDiscoveryTest(result)
    expect(plaintext.toString()).to.equal(cleartext)
  })
})
