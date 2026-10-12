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
        /* The cache reuses this data key for other messages,
         * so the backing request must not carry this message's plaintextLength.
         */
        .getEncryptionMaterials({ suite, encryptionContext, commitmentPolicy })

    // If a shared request fails, its waiting callers retry once, together.
    // If the retry fails too, they throw its error.
    const getShared = async (
      retry: boolean
    ): Promise<EncryptionMaterial<S>> => {
      /* Check for early return (Postcondition): If I have a valid EncryptionMaterial, return it. */
      const entry = this._cache.getEncryptionMaterial(cacheKey, plaintextLength)
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      // Wait on an in-flight request whose data key still has room for this message.
      const joinable = findBatch<EncryptionMaterial<S>>(
        this._cache,
        cacheKey,
        (b) => canJoin(this, b, plaintextLength)
      )
      if (joinable) {
        const outcome = await joinBatch(joinable, plaintextLength)
        if ('material' in outcome) return outcome.material
        if ('error' in outcome) {
          if (!retry) throw outcome.error
          // The failed batch is gone by the time its waiting callers resume,
          // so the first to resume starts one new request and the rest join it.
          return getShared(false)
        }
        // The data key can't be shared, so this message needs its own request.
        return cacheEncryptionMaterial(
          this,
          cacheKey,
          await fetch(),
          plaintextLength
        )
      }

      const batch = startBatch<EncryptionMaterial<S>>(
        this._cache,
        cacheKey,
        this,
        plaintextLength
      )
      let release: Outcome<EncryptionMaterial<S>> = { unshareable: true }
      try {
        const material = await fetch()

        // Not cache safe, so the waiting callers can't share it.
        if (!material.suite.cacheSafe) return material

        const used = {
          response: material,
          now: Date.now(),
          messagesEncrypted: batch.messages,
          bytesEncrypted: batch.bytes,
        }
        // canJoin keeps waiting callers within the limits,
        // so this only trips when this caller's message alone exceeds them.
        if (this._cacheEntryHasExceededLimits(used)) return material

        this._cache.putEncryptionMaterial(
          cacheKey,
          material,
          plaintextLength,
          this._maxAge
        )
        // Each getEncryptionMaterial call counts one waiting caller's message against the entry.
        for (const member of batch.members) {
          this._cache.getEncryptionMaterial(cacheKey, member.plaintextLength)
        }
        for (const member of batch.members) {
          member.settle({ material: cloneResponse(material) })
        }
        return cloneResponse(material)
      } catch (error) {
        release = { error }
        throw error
      } finally {
        // Release the callers still waiting:
        // on an error they retry once, together,
        // and on unshareable material they each make their own request.
        // After a success they already have the material and ignore this.
        closeBatch(this._cache, cacheKey, batch)
        settleMembers(batch, release)
      }
    }
    return getShared(true)
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

  const testEntry = {
    response: material,
    now: Date.now(),
    messagesEncrypted: 1,
    bytesEncrypted: plaintextLength,
  }
  /* One message can exceed the bytes or messages limit by itself.
   * Return the material for it, but don't cache a data key that is already over its limits.
   */
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
     * A clone would leave a second copy of the unencrypted data key for GC to clean up.
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

    // If a shared request fails, its waiting callers retry once, together.
    // If the retry fails too, they throw its error.
    const getShared = async (
      retry: boolean
    ): Promise<DecryptionMaterial<S>> => {
      /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
      const entry = this._cache.getDecryptionMaterial(cacheKey)
      if (entry && !this._cacheEntryHasExceededLimits(entry)) {
        return cloneResponse(entry.response)
      } else {
        this._cache.del(cacheKey)
      }

      const joinable = findBatch<DecryptionMaterial<S>>(
        this._cache,
        cacheKey,
        isRecent
      )
      if (joinable) {
        const outcome = await joinBatch(joinable, 0)
        if ('material' in outcome) return outcome.material
        if ('error' in outcome && !retry) throw outcome.error
        // The failed batch is gone by the time its waiting callers resume,
        // so the first to resume starts one new request and the rest join it.
        return getShared(false)
      }

      const batch = startBatch<DecryptionMaterial<S>>(
        this._cache,
        cacheKey,
        this,
        0
      )
      let release: Outcome<DecryptionMaterial<S>> = { unshareable: true }
      try {
        const material = await fetchAndCache()
        for (const member of batch.members) {
          member.settle({ material: cloneResponse(material) })
        }
        return cloneResponse(material)
      } catch (error) {
        release = { error }
        throw error
      } finally {
        // Release the callers still waiting with the error, so they retry once, together.
        // After a success they already have the material and ignore this.
        closeBatch(this._cache, cacheKey, batch)
        settleMembers(batch, release)
      }
    }
    return getShared(true)
  }
}

// One request to the backing materials manager, and the callers waiting on it.
interface Batch<M> {
  startedAt: number
  // Messages and bytes the data key will encrypt, counting every caller in the batch.
  // canJoin checks these against the limits before the data key exists.
  messages: number
  bytes: number
  requester: CachingMaterialsManager<any>
  members: { plaintextLength: number; settle: (outcome: Outcome<M>) => void }[]
}

// What a waiting caller gets: the material, the request's error,
// or `unshareable` if the material can't be shared with another message.
type Outcome<M> = { material: M } | { error: unknown } | { unshareable: true }

function findBatch<M>(
  cache: CryptographicMaterialsCache<any>,
  cacheKey: string,
  predicate: (batch: Batch<M>) => boolean
): Batch<M> | undefined {
  const batches = batchesByCache.get(cache)?.get(cacheKey)
  return batches?.find(predicate)
}

function isRecent(batch: Batch<any>) {
  return Date.now() < batch.startedAt + SHARED_REQUESTS.graceInterval
}

/* The batch may belong to another caching materials manager on the same cache,
 * so the joined batch must fit both managers' limits.
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

/* Call this right after findBatch finds nothing, with no await in between.
 * Otherwise concurrent callers each start their own batch.
 */
function startBatch<M>(
  cache: CryptographicMaterialsCache<any>,
  cacheKey: string,
  requester: CachingMaterialsManager<any>,
  plaintextLength: number
): Batch<M> {
  const byKey = batchesByCache.get(cache) || new Map<string, Batch<any>[]>()
  batchesByCache.set(cache, byKey)
  // A request that never settles is only removed here, once a newer one starts for the same key.
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

/* Counts this caller's message against the batch now, before the data key exists,
 * so canJoin sees it when the next caller arrives.
 */
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
