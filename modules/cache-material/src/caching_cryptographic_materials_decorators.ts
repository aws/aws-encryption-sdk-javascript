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

/* If many encrypt or decrypt calls use the cache at the same time,
 * cache misses for the same entry share one request to the backing materials manager.
 * One caller asks the backing materials manager, and the rest wait for its answer.
 * These limits stop a slow or stuck request from holding up any waiting callers.
 */
export const SHARED_REQUESTS = {
  // After a request has run this long, new callers stop waiting on it and make their own.
  graceInterval: 1000, // milliseconds == 1 second
  // A caller that has waited this long fails.
  inFlightTTL: 10 * 1000, // milliseconds == 10 seconds
}

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
    // Requests for this cache entry that other callers have in flight.
    const batches = openBatches<EncryptionMaterial<S>>(this._cache, cacheKey)
    // When this caller stops waiting on other callers' requests and fails.
    const waitUntil = Date.now() + SHARED_REQUESTS.inFlightTTL
    // Whether this caller has already retried after a shared request failed.
    let retried = false

    for (;;) {
      /* Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it. */
      const entry = this._cache.getEncryptionMaterial(cacheKey, plaintextLength)
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      /* On a miss, share another caller's in-flight request instead of making a new one
       * as long as its data key is still valid
       * (i.e. is within maxMessagesEncrypted and maxBytesEncrypted).
       * If no request has room, stop waiting and make a new one below.
       */
      const batch = batches.find((b) => canJoin(this, b, plaintextLength))
      if (!batch) break
      const outcome = await joinBatch(batch, plaintextLength, waitUntil)

      // The shared request succeeded: use its data key.
      if ('material' in outcome) return outcome.material

      /* The shared request's data key could not be cached (its suite is not cache safe),
       * so it cannot be shared, and this caller makes its own request.
       */
      if ('uncached' in outcome) {
        return cacheEncryptionMaterial(
          this,
          cacheKey,
          await fetch(),
          plaintextLength
        )
      }

      /* The request this caller waited on failed.
       * If this caller already retried once, throw the error.
       */
      if (retried) throw outcome.error
      // Otherwise, wait until that request is graceInterval old, then check the cache again.
      retried = true
      await sleep(batch.startedAt + SHARED_REQUESTS.graceInterval - Date.now())
    }

    // No request to share: make one, and let callers that arrive meanwhile share it.
    const batch = startBatch(batches, this, plaintextLength)
    try {
      const material = await fetch()
      // New callers can no longer join; the ones already waiting get this result below.
      closeBatch(batches, batch)

      // A data key whose suite is not cache safe cannot be shared:
      // waiting callers make their own requests.
      if (!material.suite.cacheSafe) {
        settleMembers(batch, { uncached: true })
        return material
      }

      /* This message alone exceeds the limits (e.g. plaintext over maxBytesEncrypted),
       * so nobody could have joined, and the data key must not be cached.
       * Return it without a clone, as cacheEncryptionMaterial does.
       */
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

      // Cache the data key, counting this caller's message.
      this._cache.putEncryptionMaterial(
        cacheKey,
        material,
        plaintextLength,
        this._maxAge
      )
      // Count the waiting callers' messages too, so later cache hits see the real usage.
      for (const member of batch.members) {
        this._cache.getEncryptionMaterial(cacheKey, member.plaintextLength)
      }
      // Give each waiting caller its own copy of the material.
      for (const member of batch.members) {
        member.settle({ material: cloneResponse(material) })
      }
      return cloneResponse(material)
    } catch (error) {
      // The request failed: waiting callers get the error and may retry.
      closeBatch(batches, batch)
      settleMembers(batch, { error })
      throw error
    }
  }
}

function cacheEncryptionMaterial<S extends SupportedAlgorithmSuites>(
  cmm: CachingMaterialsManager<S>,
  cacheKey: string,
  material: EncryptionMaterial<S>,
  plaintextLength: number
): EncryptionMaterial<S> {
  {
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
    // Requests for this cache entry that other callers have in flight.
    const batches = openBatches<DecryptionMaterial<S>>(this._cache, cacheKey)
    // When this caller stops waiting on other callers' requests and fails.
    const waitUntil = Date.now() + SHARED_REQUESTS.inFlightTTL
    // Whether this caller has already retried after a shared request failed.
    let retried = false

    for (;;) {
      /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
      const entry = this._cache.getDecryptionMaterial(cacheKey)
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      /* On a miss, share another caller's in-flight request instead of making a new one.
       * Decrypt materials have no reuse limits, so any recent request can be shared.
       * If there is none, stop waiting and make a new one below.
       */
      const batch = batches.find(isRecent)
      if (!batch) break
      const outcome = await joinBatch(batch, 0, waitUntil)

      // The shared request succeeded: use its material.
      if ('material' in outcome) return outcome.material

      /* The request this caller waited on failed
       * (decrypt responses are always cached, so failure is the only other outcome).
       * If this caller already retried once, throw the error.
       */
      if (retried) throw (outcome as Failed).error
      // Otherwise, wait until that request is graceInterval old, then check the cache again.
      retried = true
      await sleep(batch.startedAt + SHARED_REQUESTS.graceInterval - Date.now())
    }

    // No request to share: make one, and let callers that arrive meanwhile share it.
    const batch = startBatch(batches, this, 0)
    try {
      const material = await this._backingMaterialsManager.decryptMaterials(
        request
      )
      // New callers can no longer join; the ones already waiting get this result below.
      closeBatch(batches, batch)
      this._cache.putDecryptionMaterial(cacheKey, material, this._maxAge)
      // Give each waiting caller its own copy of the material.
      for (const member of batch.members) {
        member.settle({ material: cloneResponse(material) })
      }
      return cloneResponse(material)
    } catch (error) {
      // The request failed: waiting callers get the error and may retry.
      closeBatch(batches, batch)
      settleMembers(batch, { error })
      throw error
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
 * the material, `uncached` if the material cannot be shared, or the request's error.
 */
interface Failed {
  error: unknown
}
type Outcome<M> = { material: M } | { uncached: true } | Failed

/* In-flight batches by cache, then cache key.
 * Keyed by cache so caching materials managers that share a cache also share requests.
 */
const batchesByCache = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, Batch<any>[]>
>()

function openBatches<M>(
  cache: CryptographicMaterialsCache<any>,
  cacheKey: string
): Batch<M>[] {
  let byKey = batchesByCache.get(cache)
  if (!byKey) {
    byKey = new Map()
    batchesByCache.set(cache, byKey)
  }
  let batches = byKey.get(cacheKey)
  if (!batches) {
    batches = []
    byKey.set(cacheKey, batches)
  }
  return batches
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
  batches: Batch<M>[],
  requester: CachingMaterialsManager<any>,
  plaintextLength: number
): Batch<M> {
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

function closeBatch<M>(batches: Batch<M>[], batch: Batch<M>) {
  const index = batches.indexOf(batch)
  if (index !== -1) batches.splice(index, 1)
}

/* Wait for the shared request's answer, counting this caller's message against its data key.
 * Fails after inFlightTTL.
 */
async function joinBatch<M>(
  batch: Batch<M>,
  plaintextLength: number,
  waitUntil: number
): Promise<Outcome<M>> {
  batch.messages += 1
  batch.bytes += plaintextLength
  let timer: any
  const outcome = await new Promise<Outcome<M> | undefined>((resolve) => {
    timer = setTimeout(resolve, Math.max(0, waitUntil - Date.now()))
    batch.members.push({ plaintextLength, settle: resolve })
  })
  clearTimeout(timer)
  /* A caller that times out was counted when it joined, and stays counted.
   * So the data key may encrypt one message fewer than its limits allow, never one more.
   */
  needs(outcome, 'Caching materials manager inFlightTTL exceeded')
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
