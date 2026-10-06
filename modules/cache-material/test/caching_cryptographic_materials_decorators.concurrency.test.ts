// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  cacheEntryHasExceededLimits,
  getEncryptionMaterials,
  decryptMaterials,
} from '../src/caching_cryptographic_materials_decorators'
import { getLocalCryptographicMaterialsCache } from '../src/get_local_cryptographic_materials_cache'
import { buildCryptographicMaterialsCacheKeyHelpers } from '../src/build_cryptographic_materials_cache_key_helpers'
import { createHash, randomBytes } from 'crypto'
import {
  NodeAlgorithmSuite,
  AlgorithmSuiteIdentifier,
  KeyringTraceFlag,
  EncryptedDataKey,
  NodeEncryptionMaterial,
  NodeDecryptionMaterial,
  unwrapDataKey,
} from '@aws-crypto/material-management'

const suite = new NodeAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256
)
const edk = new EncryptedDataKey({
  providerId: 'keyNamespace',
  providerInfo: 'keyName',
  encryptedDataKey: new Uint8Array([1]),
})
const trace = { keyNamespace: 'keyNamespace', keyName: 'keyName' }

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

// A backing materials manager that takes a few milliseconds per request
// and returns a new data key every time.
function slowBackingMaterialsManager(fail = false) {
  const calls = { encrypt: 0, decrypt: 0 }
  const respond = async () => {
    await new Promise((resolve) => setTimeout(resolve, 5))
    if (fail) throw new Error('backing materials manager unavailable')
  }
  return {
    calls,
    async getEncryptionMaterials() {
      calls.encrypt += 1
      await respond()
      return new NodeEncryptionMaterial(suite, {})
        .setUnencryptedDataKey(randomBytes(16), {
          ...trace,
          flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY,
        })
        .addEncryptedDataKey(
          edk,
          KeyringTraceFlag.WRAPPING_KEY_ENCRYPTED_DATA_KEY
        )
    },
    async decryptMaterials() {
      calls.decrypt += 1
      await respond()
      return new NodeDecryptionMaterial(suite, {}).setUnencryptedDataKey(
        randomBytes(16),
        { ...trace, flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
      )
    },
  }
}

function cachingCMM(backing: any, maxMessagesEncrypted = 1000) {
  return {
    _partition: 'partition',
    _maxAge: 1000 * 60,
    _maxBytesEncrypted: 1000,
    _maxMessagesEncrypted: maxMessagesEncrypted,
    _cache: getLocalCryptographicMaterialsCache(100),
    _backingMaterialsManager: backing,
    _cacheEntryHasExceededLimits: cacheEntryHasExceededLimits(),
    getEncryptionMaterials: getEncryptionMaterials(cacheKeyHelpers),
    decryptMaterials: decryptMaterials(cacheKeyHelpers),
  } as any
}

const encryptRequest = { suite, encryptionContext: {}, plaintextLength: 1 }
const decryptRequest = {
  suite,
  encryptionContext: {},
  encryptedDataKeys: [edk],
}

describe('caching materials manager: concurrent cache misses (#1665)', () => {
  it('concurrent encrypts share data keys without exceeding maxMessagesEncrypted', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing, 5)

    const materials = await Promise.all(
      Array.from({ length: 10 }, () =>
        cmm.getEncryptionMaterials(encryptRequest)
      )
    )

    const usesByDataKey = new Map<string, number>()
    for (const material of materials) {
      const dataKey = Buffer.from(
        unwrapDataKey(material.getUnencryptedDataKey())
      ).toString('hex')
      usesByDataKey.set(dataKey, (usesByDataKey.get(dataKey) || 0) + 1)
    }
    expect(backing.calls.encrypt).to.equal(2)
    expect([...usesByDataKey.values()]).to.deep.equal([5, 5])
  })

  it('concurrent decrypts share one backing request', async () => {
    const backing = slowBackingMaterialsManager()
    const cmm = cachingCMM(backing)

    await Promise.all(
      Array.from({ length: 10 }, () => cmm.decryptMaterials(decryptRequest))
    )

    expect(backing.calls.decrypt).to.equal(1)
  })

  it('fails every waiting caller on a failed request, and retries on the next call', async () => {
    const backing = slowBackingMaterialsManager(true)
    const cmm = cachingCMM(backing)

    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () =>
        cmm.getEncryptionMaterials(encryptRequest)
      )
    )
    expect(results.every((r) => r.status === 'rejected')).to.equal(true)
    expect(backing.calls.encrypt).to.equal(1)

    await cmm.getEncryptionMaterials(encryptRequest).catch(() => undefined)
    expect(backing.calls.encrypt).to.equal(2)
  })
})
