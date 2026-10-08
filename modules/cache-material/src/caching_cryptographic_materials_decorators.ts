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

/* Timing for coalesced backing requests, from the MPL's storm-tracking cache defaults.
 * Times are in milliseconds.
 * Tests shorten them, so read them at call time.
 */
export const COALESCING = {
  // A request this old takes no new callers; the next caller starts another.
  graceInterval: 1000,
  // A caller that has waited this long fails.
  inFlightTTL: 10 * 1000,
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
        /* Strip any information about the plaintext from the backing request,
         * because the resulting response may be used to encrypt multiple plaintexts.
         */
        .getEncryptionMaterials({ suite, encryptionContext, commitmentPolicy })
    const batches = openBatches<EncryptionMaterial<S>>(this._cache, cacheKey)
    const waitUntil = Date.now() + COALESCING.inFlightTTL
    let retried = false

    /* Concurrent misses join an in-flight backing request that still has room in its limits.
     * Each caller that joins reserves its use of the data key before the response arrives,
     * so the data key is never used past maxMessagesEncrypted or maxBytesEncrypted.
     * A caller that does not fit starts its own request, so requests run in parallel.
     */
    for (;;) {
      const entry = this._cache.getEncryptionMaterial(cacheKey, plaintextLength)
      /* Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it. */
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      const batch = batches.find((b) => canJoin(this, b, plaintextLength))
      if (!batch) break
      const outcome = await joinBatch(batch, plaintextLength, waitUntil)
      if ('material' in outcome) return outcome.material
      if ('uncached' in outcome) {
        return cacheEncryptionMaterial(
          this,
          cacheKey,
          await fetch(),
          plaintextLength
        )
      }
      /* A failed request is retried once, then its error reaches the caller. */
      if (retried) throw outcome.error
      retried = true
      await sleep(batch.startedAt + COALESCING.graceInterval - Date.now())
    }

    const batch = startBatch(batches, this, plaintextLength)
    try {
      const material = await fetch()
      closeBatch(batches, batch)
      if (!material.suite.cacheSafe) {
        settleMembers(batch, { uncached: true })
        return material
      }
      const used = {
        response: material,
        now: Date.now(),
        messagesEncrypted: batch.messages,
        bytesEncrypted: batch.bytes,
      }
      /* A batch over its limits has no members: none could join it.
       * The requester's own use exceeds the limits, as in cacheEncryptionMaterial.
       */
      if (this._cacheEntryHasExceededLimits(used)) {
        settleMembers(batch, { uncached: true })
        return material
      }
      this._cache.putEncryptionMaterial(
        cacheKey,
        material,
        plaintextLength,
        this._maxAge
      )
      /* Count every member's use against the entry this request just put. */
      for (const member of batch.members) {
        this._cache.getEncryptionMaterial(cacheKey, member.plaintextLength)
      }
      for (const member of batch.members) {
        member.settle({ material: cloneResponse(material) })
      }
      return cloneResponse(material)
    } catch (error) {
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
    const batches = openBatches<DecryptionMaterial<S>>(this._cache, cacheKey)
    const waitUntil = Date.now() + COALESCING.inFlightTTL
    let retried = false

    /* Concurrent misses join the in-flight backing request. */
    for (;;) {
      const entry = this._cache.getDecryptionMaterial(cacheKey)
      /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      const batch = batches.find(isRecent)
      if (!batch) break
      const outcome = await joinBatch(batch, 0, waitUntil)
      if ('material' in outcome) return outcome.material
      /* A failed request is retried once, then its error reaches the caller.
       * Decrypt requests always cache their response, so the outcome is a failure.
       */
      if (retried) throw (outcome as Failed).error
      retried = true
      await sleep(batch.startedAt + COALESCING.graceInterval - Date.now())
    }

    const batch = startBatch(batches, this, 0)
    try {
      const material = await this._backingMaterialsManager.decryptMaterials(
        request
      )
      closeBatch(batches, batch)
      this._cache.putDecryptionMaterial(cacheKey, material, this._maxAge)
      for (const member of batch.members) {
        member.settle({ material: cloneResponse(material) })
      }
      return cloneResponse(material)
    } catch (error) {
      closeBatch(batches, batch)
      settleMembers(batch, { error })
      throw error
    }
  }
}

/* An in-flight backing request and the callers waiting on it.
 * `messages` and `bytes` count the uses reserved by the requester and its members.
 */
interface Batch<M> {
  startedAt: number
  messages: number
  bytes: number
  requester: CachingMaterialsManager<any>
  members: { plaintextLength: number; settle: (outcome: Outcome<M>) => void }[]
}

interface Failed {
  error: unknown
}
type Outcome<M> = { material: M } | { uncached: true } | Failed

/* Open requests per cache and cache key,
 * so caching materials managers that share a cache also share requests.
 * The map lives in this module: two copies of this package loaded in one process
 * keep separate requests for the same cache.
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

function isRecent(batch: Batch<any>) {
  return Date.now() < batch.startedAt + COALESCING.graceInterval
}

/* Whether one more use of `plaintextLength` bytes fits the batch under the limits of both managers. */
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
  /* The caller's reserved use stays counted, which only lowers the data key's remaining uses. */
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
