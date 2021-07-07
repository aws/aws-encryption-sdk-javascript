// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
chai.use(chaiAsPromised)
const { expect } = chai

import { testAES } from '../src/aes_simple'
import { testCachingCMMExample } from '../src/caching_cmm'
import { testKmsSimpleExample } from '../src/kms_simple'
import { testMultiKeyringExample } from '../src/multi_keyring'
import { testRSA } from '../src/rsa_simple'
import { testFallback } from '../src/fallback'
import { testDisableCommitmentTestExample } from '../src/disable_commitment'
import {
  kmsEncryptWithMaxEncryptedDataKeysTest,
  kmsDecryptWithMaxEncryptedDataKeysTest,
} from '../src/kms_max_encrypted_data_keys'
import { kmsMultiRegionSimpleTest } from '../src/kms_multi_region_simple'
import { kmsMultiRegionDiscoveryTest } from '../src/kms_multi_region_discovery'

describe('test', () => {
  it('testAES', async () => {
    const { plainText, plaintext } = await testAES()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testCachingCMMExample', async () => {
    const { plainText, plaintext } = await testCachingCMMExample()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testKmsSimpleExample', async () => {
    const { plainText, plaintext } = await testKmsSimpleExample()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testMultiKeyringExample', async () => {
    const { plainText, plaintext } = await testMultiKeyringExample()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testRSA', async () => {
    const { plainText, plaintext } = await testRSA()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testFallback', async () => {
    const { plainText, plaintext } = await testFallback()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('testDisableCommitmentTestExample', async () => {
    const { plainText, plaintext } = await testDisableCommitmentTestExample()
    expect(plainText).to.deep.equal(plaintext)
  })

  it('kmsEncryptWithMaxEncryptedDataKeysTest, less than max', async () => {
    const { cleartext, plaintext } =
      await kmsEncryptWithMaxEncryptedDataKeysTest(2)
    expect(plaintext).to.deep.equal(cleartext)
  })

  it('kmsEncryptWithMaxEncryptedDataKeysTest, equal to max', async () => {
    const { cleartext, plaintext } =
      await kmsEncryptWithMaxEncryptedDataKeysTest(3)
    expect(plaintext).to.deep.equal(cleartext)
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
    expect(plaintext).to.deep.equal(cleartext)
  })

  it('kmsDecryptWithMaxEncryptedDataKeysTest, equal to max', async () => {
    const { cleartext, plaintext } =
      await kmsDecryptWithMaxEncryptedDataKeysTest(3)
    expect(plaintext).to.deep.equal(cleartext)
  })

  it('kmsDecryptWithMaxEncryptedDataKeysTest, more than max', async () => {
    await expect(kmsDecryptWithMaxEncryptedDataKeysTest(4)).to.rejectedWith(
      Error,
      'maxEncryptedDataKeys exceeded.'
    )
  })

  it('kmsMultiRegionSimpleTest', async () => {
    const { plaintext, cleartext } = await kmsMultiRegionSimpleTest()
    expect(plaintext).to.deep.equal(cleartext)
  })

  it('kmsMultiRegionDiscoveryTest', async () => {
    const { cleartext, result } = await kmsMultiRegionSimpleTest()

    const { plaintext } = await kmsMultiRegionDiscoveryTest(result)
    expect(plaintext).to.deep.equal(cleartext)
  })
})
