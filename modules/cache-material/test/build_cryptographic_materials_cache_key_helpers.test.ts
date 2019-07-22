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
import { buildCryptographicMaterialsCacheKeyHelpers } from '../src/build_cryptographic_materials_cache_key_helpers'
import { encryptionContextVectors, encryptedDataKeyVectors, encryptCacheKeyVectors, decryptCacheKeyVectors } from './fixtures'
import { createHash } from 'crypto'

const fromUtf8 = (input: string) => Buffer.from(input, 'utf8')
const toUtf8 = (input: Uint8Array) => Buffer.from(input).toString('utf8')
const sha512 = async (...data: (Uint8Array|string)[]) => data
  .map(item => typeof item === 'string' ? Buffer.from(item, 'hex') : item)
  .reduce((hash, item) => hash.update(item), createHash('sha512'))
  .digest()

const {
  encryptionContextHash,
  encryptedDataKeysHash,
  buildEncryptionResponseCacheKey,
  buildDecryptionResponseCacheKey
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

describe('buildCryptographicMaterialsCacheKeyHelpers::buildEncryptionResponseCacheKey', () => {
  for (const vector of encryptCacheKeyVectors) {
    it(`${vector.id}`, async () => {
      const test = await buildEncryptionResponseCacheKey(...vector.arguments)
      expect(test).to.equal(Buffer.from(vector.id, 'base64').toString())
    })
  }
})

describe('buildCryptographicMaterialsCacheKeyHelpers::buildEncryptionResponseCacheKey', () => {
  for (const vector of decryptCacheKeyVectors) {
    it(`${vector.id}`, async () => {
      const test = await buildDecryptionResponseCacheKey(...vector.arguments)
      expect(test).to.equal(Buffer.from(vector.id, 'base64').toString())
    })
  }
})
