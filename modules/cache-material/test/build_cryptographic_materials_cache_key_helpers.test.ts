// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { buildCryptographicMaterialsCacheKeyHelpers } from '../src/build_cryptographic_materials_cache_key_helpers'
import {
  encryptionContextVectors,
  encryptedDataKeyVectors,
  encryptCacheKeyVectors,
  decryptCacheKeyVectors,
} from './fixtures'
import { createHash } from 'crypto'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString('utf8')
const sha512 = async (...data: (Uint8Array | string)[]) =>
  data
    .map((item) => (typeof item === 'string' ? Buffer.from(item, 'hex') : item))
    .reduce((hash, item) => hash.update(item), createHash('sha512'))
    .digest()

const {
  encryptionContextHash,
  encryptedDataKeysHash,
  buildEncryptionMaterialCacheKey,
  buildDecryptionMaterialCacheKey,
} = buildCryptographicMaterialsCacheKeyHelpers(fromUtf8, toUtf8, sha512)

describe('buildCryptographicMaterialsCacheKeyHelpers::encryptionContextHash', () => {
  for (const vector of encryptionContextVectors) {
    it(`${vector.name}`, async () => {
      const test = await encryptionContextHash(vector.encryptionContext)
      expect(test).to.deep.equal(vector.hash)
    })
  }
})

describe('buildCryptographicMaterialsCacheKeyHelpers::encryptedDataKeysHash', () => {
  for (const vector of encryptedDataKeyVectors) {
    it(`${vector.name}`, async () => {
      const test = await encryptedDataKeysHash([vector.edk])
      expect(test).to.have.lengthOf(1)
      expect(test[0]).to.deep.equal(vector.hash)
    })
  }
})

describe('buildCryptographicMaterialsCacheKeyHelpers::buildEncryptionMaterialCacheKey', () => {
  for (const vector of encryptCacheKeyVectors) {
    it(`${vector.id}`, async () => {
      const test = await buildEncryptionMaterialCacheKey(...vector.arguments)
      expect(test).to.equal(Buffer.from(vector.id, 'base64').toString())
    })
  }
})

describe('buildCryptographicMaterialsCacheKeyHelpers::buildEncryptionMaterialCacheKey', () => {
  for (const vector of decryptCacheKeyVectors) {
    it(`${vector.id}`, async () => {
      const test = await buildDecryptionMaterialCacheKey(...vector.arguments)
      expect(test).to.equal(Buffer.from(vector.id, 'base64').toString())
    })
  }
})
