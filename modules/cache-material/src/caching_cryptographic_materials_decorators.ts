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
  SharedRequest,
  SharedOutcome,
  closeRequest,
  findRequest,
  isRecent,
  settleMembers,
  shareRequest,
  startRequest,
  waitOn,
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
         * so don't pass this message's plaintextLength to the backing materials manager.
         */
        .getEncryptionMaterials({ suite, encryptionContext, commitmentPolicy })

    // If the request this caller waited on fails, it tries once more, and a second failure throws.
    // `retry` is false on that second try.
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

      // Another caller may already be requesting a data key for this cache entry.
      // Wait for that one if it can also encrypt this message without going over the limits.
      const joinable = findRequest<DataKeyRequest<S>>(
        this._cache,
        cacheKey,
        (r) => canJoin(this, r, plaintextLength)
      )
      if (joinable) {
        // Count this caller's message against the request now, before the data key exists,
        // so canJoin sees it when the next caller arrives.
        joinable.messages += 1
        joinable.bytes += plaintextLength
        const outcome = await waitOn(joinable, plaintextLength)
        if ('material' in outcome) return outcome.material
        if ('error' in outcome) {
          if (!retry) throw outcome.error
          // The caller that made the failed request already removed it,
          // so the first waiting caller to get here starts a new request and the others wait on that one.
          return getShared(false)
        }
        // The other caller's data key isn't cache safe, so this message can't use it.
        // Make a separate request.
        return cacheEncryptionMaterial(
          this,
          cacheKey,
          await fetch(),
          plaintextLength
        )
      }

      const batch = startRequest<DataKeyRequest<S>>(this._cache, cacheKey, {
        startedAt: Date.now(),
        messages: 1,
        bytes: plaintextLength,
        requester: this,
        members: [],
      })
      let release: SharedOutcome<EncryptionMaterial<S>> = { unshareable: true }
      try {
        const material = await fetch()

        // Not cache safe: return it without caching.
        // The waiting callers can't use it, so each makes its own request.
        if (!material.suite.cacheSafe) return material

        const used = {
          response: material,
          now: Date.now(),
          messagesEncrypted: batch.messages,
          bytesEncrypted: batch.bytes,
        }
        // This is true only if this message alone is larger than maxBytesEncrypted,
        // because canJoin turns away any caller that would go over the limits.
        // So no one is waiting; return the data key without caching it.
        if (this._cacheEntryHasExceededLimits(used)) return material

        this._cache.putEncryptionMaterial(
          cacheKey,
          material,
          plaintextLength,
          this._maxAge
        )
        // getEncryptionMaterial also adds to the entry's message and byte counts.
        // Call it once per waiting caller so the cached entry counts their messages too.
        for (const member of batch.members) {
          this._cache.getEncryptionMaterial(cacheKey, member.info)
        }
        for (const member of batch.members) {
          member.settle({ material: cloneResponse(material) })
        }
        return cloneResponse(material)
      } catch (error) {
        release = { error }
        throw error
      } finally {
        // Tell the callers still waiting how this request ended:
        // - on an error, they retry once
        // - if they can't use this data key, they each make their own request
        // After a success they already have the data key, so this does nothing.
        closeRequest(this._cache, cacheKey, batch)
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
  /* One message can be larger than maxBytesEncrypted by itself.
   * Return the data key for it, but don't cache it.
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
    return shareRequest(this._cache, cacheKey, {
      lookUp: () => {
        /* Check for early return (Postcondition): If I have a valid DecryptionMaterial, return it. */
        const entry = this._cache.getDecryptionMaterial(cacheKey)
        if (entry && !this._cacheEntryHasExceededLimits(entry)) {
          return cloneResponse(entry.response)
        } else {
          this._cache.del(cacheKey)
          return undefined
        }
      },
      fetch: async () =>
        this._backingMaterialsManager.decryptMaterials(request),
      copy: (material) => cloneResponse(material),
      put: (material) =>
        this._cache.putDecryptionMaterial(cacheKey, material, this._maxAge),
    })
  }
}

// A request for a data key, and the callers waiting on it.
// Each waiting caller's info is its plaintextLength.
interface DataKeyRequest<S extends SupportedAlgorithmSuites>
  extends SharedRequest<EncryptionMaterial<S>, number> {
  // Messages and bytes the data key will encrypt,
  // counting the caller that made the request and every caller waiting on it.
  // canJoin checks these against the limits before the data key exists.
  messages: number
  bytes: number
  requester: CachingMaterialsManager<S>
}

/* The request may come from another caching materials manager that shares this cache.
 * Join only if this caller's message stays within both managers' limits.
 */
function canJoin<S extends SupportedAlgorithmSuites>(
  cmm: CachingMaterialsManager<S>,
  request: DataKeyRequest<S>,
  plaintextLength: number
) {
  if (!isRecent(request)) return false
  const next = {
    response: undefined as any,
    now: Date.now(),
    messagesEncrypted: request.messages + 1,
    bytesEncrypted: request.bytes + plaintextLength,
  }
  return (
    !cmm._cacheEntryHasExceededLimits(next) &&
    !request.requester._cacheEntryHasExceededLimits(next)
  )
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
