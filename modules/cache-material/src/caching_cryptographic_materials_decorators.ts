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
import {
  SHARED_REQUESTS,
  SharingSettings,
  batchesByCache,
  resolveStormTracking,
} from './shared_requests'

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
    stormTracking,
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
  readOnlyProperty(obj, '_stormTracking', resolveStormTracking(stormTracking))
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
    const settings = sharingSettings(this)
    const waitUntil = Date.now() + settings.inFlightTTL

    for (;;) {
      /* Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it. */
      const entry = this._cache.getEncryptionMaterial(cacheKey, plaintextLength)
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      // If another caller's request has room for this message, wait for it instead of making a new one.
      const batch = findBatch<EncryptionMaterial<S>>(
        this._cache,
        cacheKey,
        (b) => canJoin(this, settings, b, plaintextLength)
      )
      if (!batch) {
        // No await before startBatch, or concurrent callers all find no batch and each start one.
        if (!fanOutReached(this._cache, settings, waitUntil)) break
        await sleep(SHARED_REQUESTS.sleepMilli)
        continue
      }
      const outcome = await joinBatch(batch, plaintextLength, waitUntil)
      if ('material' in outcome) return outcome.material

      /* Make this caller's own request, as it would without sharing, if
       * the shared data key can't be cached (the suite isn't cache safe), or
       * the shared request failed and storm tracking is off.
       */
      if ('uncached' in outcome || !settings.stormTracking) {
        return cacheEncryptionMaterial(
          this,
          cacheKey,
          await fetch(),
          plaintextLength
        )
      }

      // stormTracking mode: as in the MPL, try again once the failed request is graceInterval old.
      await sleep(batch.startedAt + settings.graceInterval - Date.now())
    }

    const batch = startBatch<EncryptionMaterial<S>>(
      this._cache,
      cacheKey,
      this,
      settings,
      plaintextLength
    )
    let material: EncryptionMaterial<S>
    try {
      material = await fetch()
    } catch (error) {
      closeBatch(this._cache, cacheKey, batch)
      settleMembers(batch, { error })
      throw error
    }
    closeBatch(this._cache, cacheKey, batch)

    // Can't cache it, so the waiting callers can't share it.
    if (!material.suite.cacheSafe) {
      settleMembers(batch, { uncached: true })
      return material
    }

    // This message alone is over the limits, so nobody joined, and it can't be cached.
    const used = {
      response: material,
      now: Date.now(),
      messagesEncrypted: batch.messages,
      bytesEncrypted: batch.bytes,
    }
    if (this._cacheEntryHasExceededLimits(used)) {
      settleMembers(batch, { uncached: true })
      return material
    }

    try {
      this._cache.putEncryptionMaterial(
        cacheKey,
        material,
        plaintextLength,
        this._maxAge
      )
    } catch (error) {
      settleMembers(batch, { error })
      throw error
    }
    // Count the waiting callers' messages against the cache entry too.
    for (const member of batch.members) {
      this._cache.getEncryptionMaterial(cacheKey, member.plaintextLength)
    }
    for (const member of batch.members) {
      member.settle({ material: cloneResponse(material) })
    }
    return cloneResponse(material)
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
    const settings = sharingSettings(this)
    const waitUntil = Date.now() + settings.inFlightTTL

    for (;;) {
      /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
      const entry = this._cache.getDecryptionMaterial(cacheKey)
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      // If another caller has a request in flight, wait for it instead of making a new one.
      const batch = findBatch<DecryptionMaterial<S>>(
        this._cache,
        cacheKey,
        (b) => isRecent(settings, b)
      )
      if (!batch) {
        // No await before startBatch, or concurrent callers all find no batch and each start one.
        if (!fanOutReached(this._cache, settings, waitUntil)) break
        await sleep(SHARED_REQUESTS.sleepMilli)
        continue
      }
      const outcome = await joinBatch(batch, 0, waitUntil)
      if ('material' in outcome) return outcome.material

      // The shared request failed: in default mode, make this caller's own request.
      if (!settings.stormTracking) return cloneResponse(await fetchAndCache())

      // stormTracking mode: as in the MPL, try again once the failed request is graceInterval old.
      await sleep(batch.startedAt + settings.graceInterval - Date.now())
    }

    const batch = startBatch<DecryptionMaterial<S>>(
      this._cache,
      cacheKey,
      this,
      settings,
      0
    )
    let material: DecryptionMaterial<S>
    try {
      material = await fetchAndCache()
    } catch (error) {
      closeBatch(this._cache, cacheKey, batch)
      settleMembers(batch, { error })
      throw error
    }
    closeBatch(this._cache, cacheKey, batch)
    for (const member of batch.members) {
      member.settle({ material: cloneResponse(material) })
    }
    return cloneResponse(material)
  }
}

const IN_FLIGHT_TTL_EXCEEDED = 'Caching materials manager inFlightTTL exceeded'

// Default mode has no fanOut limit and no timeout for waiting callers.
function sharingSettings(
  cmm: CachingMaterialsManager<any>
): Readonly<SharingSettings> {
  return (
    cmm._stormTracking || {
      stormTracking: false,
      graceInterval: SHARED_REQUESTS.graceInterval,
      fanOut: Infinity,
      inFlightTTL: Infinity,
    }
  )
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
  members: Member<M>[]
}

interface Member<M> {
  plaintextLength: number
  settle: (outcome: Outcome<M>) => void
}

/* What a waiting caller gets when the shared request finishes:
 * the material, `uncached` if the material cannot be shared, or the request's error.
 */
type Outcome<M> = { material: M } | { uncached: true } | { error: unknown }

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
function isRecent(settings: SharingSettings, batch: Batch<any>) {
  return Date.now() < batch.startedAt + settings.graceInterval
}

/* Whether this caller's message still fits in the batch's data key.
 * The batch may belong to another caching materials manager on the same cache,
 * so check both managers' limits.
 */
function canJoin<S extends SupportedAlgorithmSuites>(
  cmm: CachingMaterialsManager<S>,
  settings: SharingSettings,
  batch: Batch<any>,
  plaintextLength: number
) {
  if (!isRecent(settings, batch)) return false
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

/* stormTracking mode: whether fanOut requests are already in flight on this cache.
 * Throws once the caller has waited past inFlightTTL.
 */
function fanOutReached(
  cache: CryptographicMaterialsCache<any>,
  settings: SharingSettings,
  waitUntil: number
): boolean {
  if (!settings.stormTracking) return false
  if (inFlightCount(cache, settings) < settings.fanOut) return false
  needs(Date.now() <= waitUntil, IN_FLIGHT_TTL_EXCEEDED)
  return true
}

/* Requests in flight on this cache, across all cache keys.
 * As in the MPL, a request older than inFlightTTL stops counting.
 */
function inFlightCount(
  cache: CryptographicMaterialsCache<any>,
  settings: SharingSettings
) {
  const now = Date.now()
  let count = 0
  for (const batches of batchesByCache.get(cache)?.values() || []) {
    for (const batch of batches as Batch<any>[]) {
      if (now < batch.startedAt + settings.inFlightTTL) count += 1
    }
  }
  return count
}

function startBatch<M>(
  cache: CryptographicMaterialsCache<any>,
  cacheKey: string,
  requester: CachingMaterialsManager<any>,
  settings: SharingSettings,
  plaintextLength: number
): Batch<M> {
  let byKey = batchesByCache.get(cache)
  if (!byKey) {
    byKey = new Map()
    batchesByCache.set(cache, byKey)
  }
  // Drop batches nobody can join anymore.
  // This is the only place a request that never settles gets forgotten.
  const batches = (byKey.get(cacheKey) || []).filter((b) =>
    isRecent(settings, b)
  )
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

/* Wait for the shared request's answer, counting this caller's message against its data key.
 * In stormTracking mode, fails once waitUntil passes.
 */
async function joinBatch<M>(
  batch: Batch<M>,
  plaintextLength: number,
  waitUntil: number
): Promise<Outcome<M>> {
  batch.messages += 1
  batch.bytes += plaintextLength
  let timer: ReturnType<typeof setTimeout> | undefined
  const outcome = await new Promise<Outcome<M> | undefined>((resolve) => {
    const member = { plaintextLength, settle: resolve }
    batch.members.push(member)
    if (waitUntil === Infinity) return
    timer = setTimeout(() => {
      // A caller that times out never gets the data key, so stop cloning it for this caller or counting its message.
      const index = batch.members.indexOf(member)
      if (index !== -1) batch.members.splice(index, 1)
      batch.messages -= 1
      batch.bytes -= plaintextLength
      resolve(undefined)
    }, Math.max(0, waitUntil - Date.now()))
  })
  if (timer) clearTimeout(timer)
  needs(outcome, IN_FLIGHT_TTL_EXCEEDED)
  return outcome
}

function settleMembers<M>(batch: Batch<M>, outcome: Outcome<M>) {
  for (const member of batch.members) member.settle(outcome)
}

async function sleep(ms: number) {
  if (ms > 0) await new Promise((resolve) => setTimeout(resolve, ms))
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
    /** Opt in to the MPL's StormTracking behavior; see {@link CachingMaterialsManagerStormTracking}. */
    stormTracking?: CachingMaterialsManagerStormTracking
  }> {}

/**
 * Settings that make the caching materials manager share requests like the MPL's StormTracking cache.
 * Times are in milliseconds, like maxAge.
 *
 * Without stormTracking, concurrent misses for the same cache entry still share one backing request,
 * but sharing adds no new failures or waits:
 * - if the shared request fails, each waiting caller makes its own request
 * - waiting callers don't time out
 * - no limit on requests in flight
 *
 * These defaults differ from the MPL so existing customers see no change.
 * A future major version may align them.
 *
 * With stormTracking, unset settings take the MPL's defaults.
 */
export interface CachingMaterialsManagerStormTracking {
  /**
   * After a request has run this long, new callers stop waiting on it and make their own.
   * After a failed request, waiting callers try again once it is this old.
   * Default 1000.
   */
  graceInterval?: number
  /**
   * At most this many backing requests are in flight at once, across every entry in the cache.
   * Other callers wait.
   * Default 20.
   */
  fanOut?: number
  /**
   * A caller that has waited this long fails.
   * Must be at least graceInterval.
   * Default 10000.
   */
  inFlightTTL?: number
}

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
  // Set by decorateProperties when the stormTracking input is given.
  readonly _stormTracking?: Readonly<SharingSettings>

  _cacheEntryHasExceededLimits: CacheEntryHasExceededLimits<S>
}

export interface CacheEntryHasExceededLimits<
  S extends SupportedAlgorithmSuites
> {
  (entry: Entry<S>): boolean
}
