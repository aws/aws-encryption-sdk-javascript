// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  cacheEntryHasExceededLimits,
  getEncryptionMaterials,
} from '../src/caching_cryptographic_materials_decorators'
import { localCryptographicMaterialsCache } from '../src/local_cryptographic_materials_cache'
import { getLocalCryptographicMaterialsCache } from '../src/get_local_cryptographic_materials_cache'
import { clockFor } from '../src/cache_clock'
import { buildCryptographicMaterialsCacheKeyHelpers } from '../src/build_cryptographic_materials_cache_key_helpers'
import { createHash, randomBytes } from 'crypto'
import {
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  NodeAlgorithmSuite,
  NodeEncryptionMaterial,
  EncryptedDataKey,
} from '@aws-crypto/material-management'

const suite = new NodeAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
)

const cacheKeyHelpers = buildCryptographicMaterialsCacheKeyHelpers(
  (input: string) => Buffer.from(input, 'utf8'),
  (input: Uint8Array) => Buffer.from(input).toString('utf8'),
  async (...data: (Uint8Array | string)[]) =>
    data
      .map((item) =>
        typeof item === 'string' ? Buffer.from(item, 'hex') : item
      )
      .reduce((hash, item) => hash.update(item), createHash('sha512'))
      .digest()
)

describe('cache clock', () => {
  it('a cache from getLocalCryptographicMaterialsCache uses Date.now', () => {
    expect(clockFor(getLocalCryptographicMaterialsCache(1))).to.equal(Date.now)
  })

  it('a caching CMM expires entries by the clock of its cache', async () => {
    let now = 1000
    const cache = localCryptographicMaterialsCache(10, 60 * 1000, () => now)
    let backingCalls = 0
    const cmm = {
      _partition: 'partition',
      _maxAge: 100,
      _maxBytesEncrypted: 1000,
      _maxMessagesEncrypted: 1000,
      _cache: cache,
      _backingMaterialsManager: {
        async getEncryptionMaterials() {
          backingCalls += 1
          return new NodeEncryptionMaterial(suite, {})
            .setUnencryptedDataKey(randomBytes(16), {
              keyNamespace: 'k',
              keyName: 'k',
              flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
            })
            .addEncryptedDataKey(
              new EncryptedDataKey({
                providerId: 'k',
                providerInfo: 'k',
                encryptedDataKey: new Uint8Array([1]),
              }),
              KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
            )
        },
      },
      _cacheEntryHasExceededLimits: cacheEntryHasExceededLimits(),
      getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
    } as any
    const request = { suite, encryptionContext: {}, plaintextLength: 1 }

    await cmm.getEncryptionMaterials(request)
    now += 100
    await cmm.getEncryptionMaterials(request)
    expect(backingCalls).to.equal(1)

    now += 1
    await cmm.getEncryptionMaterials(request)
    expect(backingCalls).to.equal(2)
  })
})
