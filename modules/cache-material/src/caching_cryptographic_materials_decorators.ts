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
    const inFlight = inFlightRequests(this._cache)
    /* Concurrent misses wait for one backing request,
     * then read the cache again so that each use counts against the entry's limits.
     * Once an entry's limits are spent, the next waiter requests a new data key
     * while the rest wait, so N callers with a limit of L make about N/L
     * backing requests in sequence.
     * A response that cannot serve another caller is not shared:
     * waiters then request their own in parallel.
     */
    const shareable =
      plaintextLength <= this._maxBytesEncrypted &&
      this._maxMessagesEncrypted > 1
    let settle: Settle | undefined
    for (;;) {
      const entry = this._cache.getEncryptionMaterial(cacheKey, plaintextLength)
      /* Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it. */
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      if (!shareable) break
      const pending = inFlight.get(cacheKey)
      if (!pending) {
        settle = startRequest(inFlight, cacheKey)
        break
      }
      if (!(await pending)) break
    }

    try {
      const material = await this._backingMaterialsManager
        /* Strip any information about the plaintext from the backing request,
         * because the resulting response may be used to encrypt multiple plaintexts.
         */
        .getEncryptionMaterials({ suite, encryptionContext, commitmentPolicy })
      const response = cacheEncryptionMaterial(
        this,
        cacheKey,
        material,
        plaintextLength
      )
      settle && settle({ shared: response.shared })
      return response.material
    } catch (error) {
      settle && settle({ error })
      throw error
    }
  }
}

function cacheEncryptionMaterial<S extends SupportedAlgorithmSuites>(
  cmm: CachingMaterialsManager<S>,
  cacheKey: string,
  material: EncryptionMaterial<S>,
  plaintextLength: number
): { material: EncryptionMaterial<S>; shared: boolean } {
  /* Check for early return (Postcondition): If I can not cache the EncryptionMaterial, just return it. */
  if (!material.suite.cacheSafe) return { material, shared: false }

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
  if (!cmm._cacheEntryHasExceededLimits(testEntry)) {
    cmm._cache.putEncryptionMaterial(
      cacheKey,
      material,
      plaintextLength,
      cmm._maxAge
    )
    return { material: cloneResponse(material), shared: true }
  } else {
    /* Postcondition: If the material has exceeded limits it MUST NOT be cloned.
     * If it is cloned, and the clone is returned,
     * then there exist a copy of the unencrypted data key.
     * It is true that this data would be caught by GC, it is better to just not rely on that.
     */
    return { material, shared: false }
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
    const inFlight = inFlightRequests(this._cache)
    /* Concurrent misses wait for one backing request, then read the cache again. */
    for (;;) {
      const entry = this._cache.getDecryptionMaterial(cacheKey)
      /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      const pending = inFlight.get(cacheKey)
      if (!pending) break
      await pending
    }

    const settle = startRequest(inFlight, cacheKey)
    try {
      const material = await this._backingMaterialsManager.decryptMaterials(
        request
      )
      this._cache.putDecryptionMaterial(cacheKey, material, this._maxAge)
      settle({ shared: true })
      return cloneResponse(material)
    } catch (error) {
      settle({ error })
      throw error
    }
  }
}

/* In-flight backing requests are tracked per cache,
 * so caching materials managers that share a cache also share requests.
 * Each resolves to whether its response can serve a waiting caller.
 * Callers already waiting share a failed request's error; later calls retry.
 */
const inFlightByCache = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, Promise<boolean>>
>()

function inFlightRequests(
  cache: CryptographicMaterialsCache<any>
): Map<string, Promise<boolean>> {
  let inFlight = inFlightByCache.get(cache)
  if (!inFlight) {
    inFlight = new Map()
    inFlightByCache.set(cache, inFlight)
  }
  return inFlight
}

type Settle = (result: { shared: boolean } | { error: unknown }) => void

/* Marks a backing request for `cacheKey` as in flight.
 * The returned function removes it and resolves or rejects its waiting callers.
 */
function startRequest(
  inFlight: Map<string, Promise<boolean>>,
  cacheKey: string
): Settle {
  let resolve!: (shared: boolean) => void
  let reject!: (error: unknown) => void
  const pending = new Promise<boolean>((res, rej) => {
    resolve = res
    reject = rej
  })
  /* The requesting caller throws the error itself; only waiting callers read it from here. */
  pending.catch(() => undefined)
  inFlight.set(cacheKey, pending)
  return (result) => {
    if (inFlight.get(cacheKey) === pending) inFlight.delete(cacheKey)
    if ('error' in result) reject(result.error)
    else resolve(result.shared)
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
