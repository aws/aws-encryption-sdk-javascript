// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  GetEncryptionMaterials,
  GetDecryptMaterials,
  DecryptionMaterial,
  SupportedAlgorithmSuites,
  EncryptionRequest,
  EncryptionMaterial,
  MaterialsManager,
  DecryptionRequest,
  needs,
  readOnlyProperty,
  Keyring,
  cloneMaterial,
} from '@aws-crypto/material-management'
import { Maximum } from '@aws-crypto/serialize'
import {
  CryptographicMaterialsCache,
  Entry,
} from './cryptographic_materials_cache'
import { CryptographicMaterialsCacheKeyHelpersInterface } from './build_cryptographic_materials_cache_key_helpers'

export function decorateProperties<S extends SupportedAlgorithmSuites>(
  obj: CachingMaterialsManager<S>,
  input: CachingMaterialsManagerDecorateInput<S>
) {
  const {
    cache,
    backingMaterialsManager,
    maxAge,
    maxBytesEncrypted,
    maxMessagesEncrypted,
    partition,
  } = input

  /* Precondition: A caching material manager needs a cache. */
  needs(cache, 'You must provide a cache.')
  /* Precondition: A caching material manager needs a way to get material. */
  needs(backingMaterialsManager, 'You must provide a backing material source.')
  /* Precondition: You *can not* cache something forever. */
  needs(maxAge > 0, 'You must configure a maxAge')
  /* Precondition: maxBytesEncrypted must be inside bounds.  i.e. positive and not more than the maximum. */
  needs(
    !maxBytesEncrypted ||
      (maxBytesEncrypted > 0 &&
        Maximum.BYTES_PER_CACHED_KEY_LIMIT >= maxBytesEncrypted),
    'maxBytesEncrypted is outside of bounds.'
  )
  /* Precondition: maxMessagesEncrypted must be inside bounds.  i.e. positive and not more than the maximum. */
  needs(
    !maxMessagesEncrypted ||
      (maxMessagesEncrypted > 0 &&
        Maximum.MESSAGES_PER_CACHED_KEY_LIMIT >= maxMessagesEncrypted),
    'maxMessagesEncrypted is outside of bounds.'
  )
  /* Precondition: partition must be a string. */
  needs(
    partition && typeof partition === 'string',
    'partition must be a string.'
  )

  readOnlyProperty(obj, '_cache', cache)
  readOnlyProperty(obj, '_backingMaterialsManager', backingMaterialsManager)
  readOnlyProperty(obj, '_maxAge', maxAge)
  readOnlyProperty(
    obj,
    '_maxBytesEncrypted',
    maxBytesEncrypted || Maximum.BYTES_PER_CACHED_KEY_LIMIT
  )
  readOnlyProperty(
    obj,
    '_maxMessagesEncrypted',
    maxMessagesEncrypted || Maximum.MESSAGES_PER_CACHED_KEY_LIMIT
  )
  readOnlyProperty(obj, '_partition', partition)
}

export function getEncryptionMaterials<S extends SupportedAlgorithmSuites>({
  buildEncryptionMaterialCacheKey,
}: CryptographicMaterialsCacheKeyHelpersInterface<S>): GetEncryptionMaterials<S> {
  return async function getEncryptionMaterials(
    this: CachingMaterialsManager<S>,
    request: EncryptionRequest<S>
  ): Promise<EncryptionMaterial<S>> {
    const { suite, encryptionContext, plaintextLength, commitmentPolicy } =
      request

    /* Check for early return (Postcondition): If I can not cache the EncryptionMaterial, do not even look. */
    if (
      (suite && !suite.cacheSafe) ||
      typeof plaintextLength !== 'number' ||
      plaintextLength < 0
    ) {
      const material =
        await this._backingMaterialsManager.getEncryptionMaterials(request)
      return material
    }

    const cacheKey = await buildEncryptionMaterialCacheKey(this._partition, {
      suite,
      encryptionContext,
    })
    const entry = this._cache.getEncryptionMaterial(cacheKey, plaintextLength)
    /* Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it. */
    if (entry && !this._cacheEntryHasExceededLimits(entry)) {
      return cloneResponse(entry.response)
    } else {
      this._cache.del(cacheKey)
    }

    const material = await this._backingMaterialsManager
      /* Strip any information about the plaintext from the backing request,
       * because the resulting response may be used to encrypt multiple plaintexts.
       */
      .getEncryptionMaterials({ suite, encryptionContext, commitmentPolicy })

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
      bytesEncrypted: plaintextLength,
    }
    if (!this._cacheEntryHasExceededLimits(testEntry)) {
      this._cache.putEncryptionMaterial(
        cacheKey,
        material,
        plaintextLength,
        this._maxAge
      )
      return cloneResponse(material)
    } else {
      /* Postcondition: If the material has exceeded limits it MUST NOT be cloned.
       * If it is cloned, and the clone is returned,
       * then there exist a copy of the unencrypted data key.
       * It is true that this data would be caught by GC, it is better to just not rely on that.
       */
      return material
    }
  }
}

export function decryptMaterials<S extends SupportedAlgorithmSuites>({
  buildDecryptionMaterialCacheKey,
}: CryptographicMaterialsCacheKeyHelpersInterface<S>): GetDecryptMaterials<S> {
  return async function decryptMaterials(
    this: CachingMaterialsManager<S>,
    request: DecryptionRequest<S>
  ): Promise<DecryptionMaterial<S>> {
    const { suite } = request
    /* Check for early return (Postcondition): If I can not cache the DecryptionMaterial, do not even look. */
    if (!suite.cacheSafe) {
      const material = await this._backingMaterialsManager.decryptMaterials(
        request
      )
      return material
    }

    const cacheKey = await buildDecryptionMaterialCacheKey(
      this._partition,
      request
    )
    const entry = this._cache.getDecryptionMaterial(cacheKey)
    /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
    if (entry && !this._cacheEntryHasExceededLimits(entry)) {
      return cloneResponse(entry.response)
    } else {
      this._cache.del(cacheKey)
    }

    const material = await this._backingMaterialsManager.decryptMaterials(
      request
    )

    this._cache.putDecryptionMaterial(cacheKey, material, this._maxAge)
    return cloneResponse(material)
  }
}

export function cacheEntryHasExceededLimits<
  S extends SupportedAlgorithmSuites
>(): CacheEntryHasExceededLimits<S> {
  return function cacheEntryHasExceededLimits(
    this: CachingMaterialsManager<S>,
    { now, messagesEncrypted, bytesEncrypted }: Entry<S>
  ): boolean {
    const age = Date.now() - now
    return (
      age > this._maxAge ||
      messagesEncrypted > this._maxMessagesEncrypted ||
      bytesEncrypted > this._maxBytesEncrypted
    )
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
function cloneResponse<
  S extends SupportedAlgorithmSuites,
  M extends EncryptionMaterial<S> | DecryptionMaterial<S>
>(material: M): M {
  return cloneMaterial(material)
}

export interface CachingMaterialsManagerInput<
  S extends SupportedAlgorithmSuites
> extends Readonly<{
    cache: CryptographicMaterialsCache<S>
    backingMaterials: MaterialsManager<S> | Keyring<S>
    partition?: string
    maxBytesEncrypted?: number
    maxMessagesEncrypted?: number
    maxAge: number
  }> {}

export interface CachingMaterialsManagerDecorateInput<
  S extends SupportedAlgorithmSuites
> extends CachingMaterialsManagerInput<S> {
  backingMaterialsManager: MaterialsManager<S>
  partition: string
}

export interface CachingMaterialsManager<S extends SupportedAlgorithmSuites>
  extends MaterialsManager<S> {
  readonly _partition: string
  readonly _cache: CryptographicMaterialsCache<S>
  readonly _backingMaterialsManager: MaterialsManager<S>
  readonly _maxBytesEncrypted: number
  readonly _maxMessagesEncrypted: number
  readonly _maxAge: number

  _cacheEntryHasExceededLimits: CacheEntryHasExceededLimits<S>
}

export interface CacheEntryHasExceededLimits<
  S extends SupportedAlgorithmSuites
> {
  (entry: Entry<S>): boolean
}
