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
import { SHARED_REQUESTS, batchesByCache } from './shared_requests'

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
    const fetch = async () =>
      this._backingMaterialsManager
        /* Leave plaintextLength out of the request to the backing materials manager.
         * The data key it returns is cached and reused for other messages,
         * so it must not depend on this message's length.
         */
        .getEncryptionMaterials({ suite, encryptionContext, commitmentPolicy })

    /* Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it. */
    const entry = this._cache.getEncryptionMaterial(cacheKey, plaintextLength)
    if (entry && !this._cacheEntryHasExceededLimits(entry)) {
      return cloneResponse(entry.response)
    } else {
      this._cache.del(cacheKey)
    }

    // If another caller's request has room for this message, wait for it instead of making a new one.
    const joinable = findBatch<EncryptionMaterial<S>>(
      this._cache,
      cacheKey,
      (b) => canJoin(this, b, plaintextLength)
    )
    if (joinable) {
      const outcome = await joinBatch(joinable, plaintextLength)
      if ('material' in outcome) return outcome.material
      /* The shared data key can't be cached, or the shared request failed.
       * Make this caller's own request, as it would without sharing.
       */
      return cacheEncryptionMaterial(
        this,
        cacheKey,
        await fetch(),
        plaintextLength
      )
    }

    // No await between findBatch and startBatch, or concurrent callers all find no batch and each start one.
    const batch = startBatch<EncryptionMaterial<S>>(
      this._cache,
      cacheKey,
      this,
      plaintextLength
    )
    try {
      const material = await fetch()

      // Can't cache it, so the waiting callers can't share it.
      if (!material.suite.cacheSafe) return material

      // This message alone is over the limits, so nobody joined, and it can't be cached.
      const used = {
        response: material,
        now: Date.now(),
        messagesEncrypted: batch.messages,
        bytesEncrypted: batch.bytes,
      }
      if (this._cacheEntryHasExceededLimits(used)) return material

      this._cache.putEncryptionMaterial(
        cacheKey,
        material,
        plaintextLength,
        this._maxAge
      )
      // Count the waiting callers' messages against the cache entry too.
      for (const member of batch.members) {
        this._cache.getEncryptionMaterial(cacheKey, member.plaintextLength)
      }
      for (const member of batch.members) {
        member.settle({ material: cloneResponse(material) })
      }
      return cloneResponse(material)
    } finally {
      // However this request ends, waiting callers not given its material make their own.
      closeBatch(this._cache, cacheKey, batch)
      settleMembers(batch, { failed: true })
    }
  }
}

function cacheEncryptionMaterial<S extends SupportedAlgorithmSuites>(
  cmm: CachingMaterialsManager<S>,
  cacheKey: string,
  material: EncryptionMaterial<S>,
  plaintextLength: number
): EncryptionMaterial<S> {
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
  if (!cmm._cacheEntryHasExceededLimits(testEntry)) {
    cmm._cache.putEncryptionMaterial(
      cacheKey,
      material,
      plaintextLength,
      cmm._maxAge
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
    const fetchAndCache = async () => {
      const material = await this._backingMaterialsManager.decryptMaterials(
        request
      )
      this._cache.putDecryptionMaterial(cacheKey, material, this._maxAge)
      return material
    }

    /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
    const entry = this._cache.getDecryptionMaterial(cacheKey)
    if (entry && !this._cacheEntryHasExceededLimits(entry)) {
      return cloneResponse(entry.response)
    } else {
      this._cache.del(cacheKey)
    }

    // If another caller has a request in flight, wait for it instead of making a new one.
    const joinable = findBatch<DecryptionMaterial<S>>(
      this._cache,
      cacheKey,
      isRecent
    )
    if (joinable) {
      const outcome = await joinBatch(joinable, 0)
      if ('material' in outcome) return outcome.material
      // The shared request failed: make this caller's own request, as it would without sharing.
      return cloneResponse(await fetchAndCache())
    }

    // No await between findBatch and startBatch, or concurrent callers all find no batch and each start one.
    const batch = startBatch<DecryptionMaterial<S>>(
      this._cache,
      cacheKey,
      this,
      0
    )
    try {
      const material = await fetchAndCache()
      for (const member of batch.members) {
        member.settle({ material: cloneResponse(material) })
      }
      return cloneResponse(material)
    } finally {
      // However this request ends, waiting callers not given its material make their own.
      closeBatch(this._cache, cacheKey, batch)
      settleMembers(batch, { failed: true })
    }
  }
}

/* One request to the backing materials manager, plus the callers waiting for its answer.
 * `messages` and `bytes` count what its data key will encrypt for all of them,
 * so canJoin can keep the data key within its limits before it even exists.
 */
interface Batch<M> {
  startedAt: number
  messages: number
  bytes: number
  requester: CachingMaterialsManager<any>
  members: { plaintextLength: number; settle: (outcome: Outcome<M>) => void }[]
}

/* What a waiting caller gets when the shared request finishes:
 * the material, or `failed` if the request failed or its material can't be shared.
 * A caller's settle is a promise resolve, so only the first outcome counts.
 */
type Outcome<M> = { material: M } | { failed: true }

// Look up the list on every call: closeBatch deletes a key's list once it is empty.
function findBatch<M>(
  cache: CryptographicMaterialsCache<any>,
  cacheKey: string,
  predicate: (batch: Batch<M>) => boolean
): Batch<M> | undefined {
  const batches = batchesByCache.get(cache)?.get(cacheKey)
  return batches?.find(predicate)
}

/* A request older than graceInterval may be stuck, so new callers stop sharing it. */
function isRecent(batch: Batch<any>) {
  return Date.now() < batch.startedAt + SHARED_REQUESTS.graceInterval
}

/* Whether this caller's message still fits in the batch's data key.
 * The batch may belong to another caching materials manager on the same cache,
 * so check both managers' limits.
 */
function canJoin<S extends SupportedAlgorithmSuites>(
  cmm: CachingMaterialsManager<S>,
  batch: Batch<any>,
  plaintextLength: number
) {
  if (!isRecent(batch)) return false
  const next = {
    response: undefined as any,
    now: Date.now(),
    messagesEncrypted: batch.messages + 1,
    bytesEncrypted: batch.bytes + plaintextLength,
  }
  return (
    !cmm._cacheEntryHasExceededLimits(next) &&
    !batch.requester._cacheEntryHasExceededLimits(next)
  )
}

function startBatch<M>(
  cache: CryptographicMaterialsCache<any>,
  cacheKey: string,
  requester: CachingMaterialsManager<any>,
  plaintextLength: number
): Batch<M> {
  const byKey = batchesByCache.get(cache) || new Map<string, Batch<any>[]>()
  batchesByCache.set(cache, byKey)
  // Drop batches nobody can join anymore.
  // This is the only place a request that never settles gets forgotten.
  const batches = (byKey.get(cacheKey) || []).filter(isRecent)
  byKey.set(cacheKey, batches)
  const batch: Batch<M> = {
    startedAt: Date.now(),
    messages: 1,
    bytes: plaintextLength,
    requester,
    members: [],
  }
  batches.push(batch)
  return batch
}

// Also deletes the cache key's list once it is empty, so the map doesn't grow with every key ever used.
function closeBatch<M>(
  cache: CryptographicMaterialsCache<any>,
  cacheKey: string,
  batch: Batch<M>
) {
  const byKey = batchesByCache.get(cache)
  const batches = byKey?.get(cacheKey)
  if (!byKey || !batches) return
  const index = batches.indexOf(batch)
  if (index !== -1) batches.splice(index, 1)
  if (!batches.length) byKey.delete(cacheKey)
}

/* Wait for the shared request's answer, counting this caller's message against its data key. */
async function joinBatch<M>(
  batch: Batch<M>,
  plaintextLength: number
): Promise<Outcome<M>> {
  batch.messages += 1
  batch.bytes += plaintextLength
  return new Promise<Outcome<M>>((settle) =>
    batch.members.push({ plaintextLength, settle })
  )
}

function settleMembers<M>(batch: Batch<M>, outcome: Outcome<M>) {
  for (const member of batch.members) member.settle(outcome)
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
