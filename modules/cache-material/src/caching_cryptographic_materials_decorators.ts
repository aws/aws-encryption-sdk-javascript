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

import {
  GetEncryptionMaterials, // eslint-disable-line no-unused-vars
  GetDecryptMaterials, // eslint-disable-line no-unused-vars
  DecryptionMaterial, // eslint-disable-line no-unused-vars
  SupportedAlgorithmSuites, // eslint-disable-line no-unused-vars
  EncryptionRequest, // eslint-disable-line no-unused-vars
  EncryptionMaterial, // eslint-disable-line no-unused-vars
  MaterialsManager, // eslint-disable-line no-unused-vars
  DecryptionRequest, // eslint-disable-line no-unused-vars
  needs,
  readOnlyProperty,
  Keyring // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management'
import { Maximum } from '@aws-crypto/serialize'
import {
  CryptographicMaterialsCache, // eslint-disable-line no-unused-vars
  Entry // eslint-disable-line no-unused-vars
} from './cryptographic_materials_cache'
import {
  CryptographicMaterialsCacheKeyHelpersInterface // eslint-disable-line no-unused-vars
} from './build_cryptographic_materials_cache_key_helpers'
import { cloneMaterial } from './clone_cryptographic_material'

export function decorateProperties<S extends SupportedAlgorithmSuites> (
  obj: CachingMaterialsManager<S>,
  input: CachingMaterialsManagerDecorateInput<S>
) {
  const { cache, backingMaterialsManager, maxAge, maxBytesEncrypted, maxMessagesEncrypted, partition } = input

  /* Precondition: A caching material manager needs a cache. */
  needs(cache, 'You must provide a cache.')
  /* Precondition: A caching material manager needs a way to get material. */
  needs(backingMaterialsManager, 'You must provide a backing material source.')
  /* Precondition: You *can not* cache something forever. */
  needs(maxAge > 0, 'You must configure a maxAge')
  /* Precondition: maxBytesEncrypted must be inside bounds.  i.e. positive and not more than the maximum. */
  needs(!maxBytesEncrypted || (maxBytesEncrypted > 0 && Maximum.BYTES_PER_KEY >= maxBytesEncrypted), 'maxBytesEncrypted is outside of bounds.')
  /* Precondition: maxMessagesEncrypted must be inside bounds.  i.e. positive and not more than the maximum. */
  needs(!maxMessagesEncrypted || (maxMessagesEncrypted > 0 && Maximum.MESSAGES_PER_KEY >= maxMessagesEncrypted), 'maxMessagesEncrypted is outside of bounds.')
  /* Precondition: partition must be a string. */
  needs(partition && typeof partition === 'string', 'partition must be a string.')

  readOnlyProperty(obj, '_cache', cache)
  readOnlyProperty(obj, '_backingMaterialsManager', backingMaterialsManager)
  readOnlyProperty(obj, '_maxAge', maxAge)
  readOnlyProperty(obj, '_maxBytesEncrypted', maxBytesEncrypted || Maximum.BYTES_PER_KEY)
  readOnlyProperty(obj, '_maxMessagesEncrypted', maxMessagesEncrypted || Maximum.MESSAGES_PER_KEY)
  readOnlyProperty(obj, '_partition', partition)
}

export function getEncryptionMaterials<S extends SupportedAlgorithmSuites> (
  { buildEncryptionMaterialCacheKey }: CryptographicMaterialsCacheKeyHelpersInterface<S>
): GetEncryptionMaterials<S> {
  return async function getEncryptionMaterials (
    this: CachingMaterialsManager<S>,
    request: EncryptionRequest<S>
  ): Promise<EncryptionMaterial<S>> {
    const { suite, encryptionContext, plaintextLength } = request
    /* Check for early return (Postcondition): If I can not cache the EncryptionMaterial, do not even look. */
    if ((suite && !suite.cacheSafe) || typeof plaintextLength !== 'number' || plaintextLength < 0) {
      return this
        ._backingMaterialsManager
        .getEncryptionMaterials(request)
    }

    const cacheKey = await buildEncryptionMaterialCacheKey(this._partition, { suite, encryptionContext })
    const entry = this._cache.getEncryptionMaterial(cacheKey, plaintextLength)
    /* Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it. */
    if (entry && !this._cacheEntryHasExceededLimits(entry)) {
      return cloneResponse(entry.response)
    } else {
      this._cache.del(cacheKey)
    }

    const material = await this
      ._backingMaterialsManager
      /* Strip any information about the plaintext from the backing request,
       * because the resulting response may be used to encrypt multiple plaintexts.
       */
      .getEncryptionMaterials({ suite, encryptionContext, plaintextLength })

    /* Check for early return (Postcondition): If I can not cache the EncryptionMaterial, just return it. */
    if (!material.suite.cacheSafe) return material

    /* It is possible for an entry to exceed limits immediately.
     * The simplest case is to need to encrypt more than then maxBytesEncrypted.
     * In this case, I return the response to encrypt the data,
     * but do not put a know invalid item into the cache.
     */
    const testEntry = {
      response: material,
      now: Date.now(),
      messagesEncrypted: 1,
      bytesEncrypted: plaintextLength
    }
    if (!this._cacheEntryHasExceededLimits(testEntry)) {
      this._cache.putEncryptionMaterial(cacheKey, material, plaintextLength, this._maxAge)
    }

    return cloneResponse(material)
  }
}

export function decryptMaterials<S extends SupportedAlgorithmSuites> (
  { buildDecryptionMaterialCacheKey }: CryptographicMaterialsCacheKeyHelpersInterface<S>
): GetDecryptMaterials<S> {
  return async function decryptMaterials (
    this: CachingMaterialsManager<S>,
    request: DecryptionRequest<S>
  ): Promise<DecryptionMaterial<S>> {
    const { suite } = request
    /* Check for early return (Postcondition): If I can not cache the DecryptionMaterial, do not even look. */
    if (!suite.cacheSafe) {
      return this
        ._backingMaterialsManager
        .decryptMaterials(request)
    }

    const cacheKey = await buildDecryptionMaterialCacheKey(this._partition, request)
    const entry = this._cache.getDecryptionMaterial(cacheKey)
    /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
    if (entry && !this._cacheEntryHasExceededLimits(entry)) {
      return cloneResponse(entry.response)
    } else {
      this._cache.del(cacheKey)
    }

    const material = await this
      ._backingMaterialsManager
      .decryptMaterials(request)

    this._cache.putDecryptionMaterial(cacheKey, material, this._maxAge)
    return cloneResponse(material)
  }
}

export function cacheEntryHasExceededLimits<S extends SupportedAlgorithmSuites> (): CacheEntryHasExceededLimits<S> {
  return function cacheEntryHasExceededLimits (
    this: CachingMaterialsManager<S>,
    { now, messagesEncrypted, bytesEncrypted }: Entry<S>
  ): boolean {
    const age = Date.now() - now
    return age > this._maxAge ||
      messagesEncrypted > this._maxMessagesEncrypted ||
      bytesEncrypted > this._maxBytesEncrypted
  }
}

/**
 * I need to clone the underlying material.
 * Because when the Encryption SDK is done with material, it will zero it out.
 * Plucking off the material and cloning just that and then returning the rest of the response
 * can just be handled in one place.
 * @param material EncryptionMaterial|DecryptionMaterial
 * @return EncryptionMaterial|DecryptionMaterial
 */
function cloneResponse<S extends SupportedAlgorithmSuites, M extends EncryptionMaterial<S>|DecryptionMaterial<S>> (
  material: M
): M {
  return cloneMaterial(material)
}

export interface CachingMaterialsManagerInput<S extends SupportedAlgorithmSuites> extends Readonly<{
  cache: CryptographicMaterialsCache<S>
  backingMaterials: MaterialsManager<S>|Keyring<S>
  partition?: string
  maxBytesEncrypted?: number
  maxMessagesEncrypted?: number
  maxAge: number
}>{}

export interface CachingMaterialsManagerDecorateInput<S extends SupportedAlgorithmSuites> extends CachingMaterialsManagerInput<S> {
  backingMaterialsManager: MaterialsManager<S>
  partition: string
}

export interface CachingMaterialsManager<S extends SupportedAlgorithmSuites> extends MaterialsManager<S> {
  readonly _partition: string
  readonly _cache: CryptographicMaterialsCache<S>
  readonly _backingMaterialsManager: MaterialsManager<S>
  readonly _maxBytesEncrypted: number
  readonly _maxMessagesEncrypted: number
  readonly _maxAge: number

  _cacheEntryHasExceededLimits: CacheEntryHasExceededLimits<S>
}

export interface CacheEntryHasExceededLimits<S extends SupportedAlgorithmSuites> {
  (entry: Entry<S>): boolean
}
