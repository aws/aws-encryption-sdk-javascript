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
  GetEncryptionMaterials,
  GetDecryptMaterials,
  DecryptionResponse,
  SupportedAlgorithmSuites,
  EncryptionRequest,
  EncryptionResponse,
  MaterialsManager,
  DecryptionRequest,
  needs,
  readOnlyProperty,
  Keyring
} from '@aws-crypto/material-management'
import {Maximum} from '@aws-crypto/serialize'
import {CryptographicMaterialsCache, Entry} from './cryptographic_materials_cache'
import {CryptographicMaterialsCacheKeyHelpersInterface} from './build_cryptographic_materials_cache_key_helpers'
import {cloneMaterial} from './clone_cryptographic_material'

export function decorateProperties<S extends SupportedAlgorithmSuites>(
  obj: CachingMaterialsManager<S>,
  input: CachingMaterialsManagerDecorateInput<S>
) {
  const {cache, backingMaterialsManager, maxAge, maxBytesEncrypted, maxMessagesEncrypted} = input

  needs(cache, '')
  needs(backingMaterialsManager, '')
  needs(!maxAge || maxAge > 0, '')
  needs(!maxBytesEncrypted || (maxBytesEncrypted > 0 && Maximum.BYTES_PER_KEY > maxBytesEncrypted), '')
  needs(!maxMessagesEncrypted || (maxMessagesEncrypted > 0 && Maximum.MESSAGES_PER_KEY > maxMessagesEncrypted), '')

  readOnlyProperty(obj, '_cache', cache)
  readOnlyProperty(obj, '_backingMaterialsManager', backingMaterialsManager)
  readOnlyProperty(obj, '_maxAge', maxAge)
  readOnlyProperty(obj, '_maxBytesEncrypted', maxBytesEncrypted || Maximum.BYTES_PER_KEY)
  readOnlyProperty(obj, '_maxMessagesEncrypted', maxMessagesEncrypted || Maximum.MESSAGES_PER_KEY)
}

export function getEncryptionMaterials<S extends SupportedAlgorithmSuites>(
  {buildEncryptionResponseCacheKey}: CryptographicMaterialsCacheKeyHelpersInterface<S>
): GetEncryptionMaterials<S> {
  return async function getEncryptionMaterials(
    this: CachingMaterialsManager<S>,
    request: EncryptionRequest<S>
  ): Promise<EncryptionResponse<S>> {
    const {suite, encryptionContext, frameLength, plaintextLength} = request
    /* Check for early return (Postcondition): If I can not cache the EncryptionResponse, do not even look. */
    if ((suite && !suite.cacheSafe) || typeof plaintextLength !== 'number') {
      return this
        ._backingMaterialsManager
        .getEncryptionMaterials(request)
    }

    const cacheKey = await buildEncryptionResponseCacheKey(this._partition, {suite, encryptionContext})
    const entry = this._cache.getEncryptionResponse(cacheKey, plaintextLength)
    /* Check for early return (Postcondition): If I have a valid EncryptionResponse, return it. */
    if (entry && !this._cacheEntryHasExceededLimits(entry)) {
      return cloneResponse(entry.response)
    } else {
      this._cache.del(cacheKey)
    }

    const response = await this
      ._backingMaterialsManager
      /* Strip any information about the plaintext from the backing request,
       * because the resulting response may be used to encrypt multiple plaintexts.
       */
      .getEncryptionMaterials({suite, encryptionContext, frameLength})

    /* Check for early return (Postcondition): If I can not cache the EncryptionResponse, just return it. */
    if (!response.material.suite.cacheSafe) return response

    /* It is possible for an entry to exceed limits immediately.
     * The simplest case is to need to encrypt more than then maxBytesEncrypted.
     * In this case, I return the response to encrypt the data,
     * but do not put a know invalid item into the cache.
     */
    const testEntry = {
      response,
      now: Date.now(),
      messagesEncrypted: 1,
      bytesEncrypted: plaintextLength
    }
    if (!this._cacheEntryHasExceededLimits(testEntry)) {
      this._cache.putEncryptionResponse(cacheKey, response, plaintextLength, this._maxAge)
    }
    
    return cloneResponse(response)
  }
}

export function decryptMaterials<S extends SupportedAlgorithmSuites>(
  {buildDecryptionResponseCacheKey}: CryptographicMaterialsCacheKeyHelpersInterface<S>
): GetDecryptMaterials<S> {
  return async function decryptMaterials(
    this: CachingMaterialsManager<S>,
    request: DecryptionRequest<S>
  ): Promise<DecryptionResponse<S>> {

    const {suite} = request
    /* Check for early return (Postcondition): If I can not cache the DecryptionResponse, do not even look. */
    if (!suite.cacheSafe) {
      return this
        ._backingMaterialsManager
        .decryptMaterials(request)
    }

    const cacheKey = await buildDecryptionResponseCacheKey(this._partition, request)
    const entry = this._cache.getDecryptionResponse(cacheKey)
    /* Check for early return (Postcondition): If I have a valid DecryptionResponse, return it. */
    if (entry && !this._cacheEntryHasExceededLimits(entry)) {
      return cloneResponse(entry.response)
    } else {
      this._cache.del(cacheKey)
    }

    const response = await this
      ._backingMaterialsManager
      .decryptMaterials(request)

    this._cache.putDecryptionResponse(cacheKey, response, this._maxAge)
    return cloneResponse(response)
  }
}

export function cacheEntryHasExceededLimits<S extends SupportedAlgorithmSuites>(): CacheEntryHasExceededLimits<S> {
  return function cacheEntryHasExceededLimits(
    this: CachingMaterialsManager<S>,
    {now, messagesEncrypted, bytesEncrypted}: Entry<S>
  ): boolean {
    const age = Date.now() - now
    return (!this._maxAge || age > this._maxAge) ||
      messagesEncrypted > this._maxMessagesEncrypted ||
      bytesEncrypted > this._maxBytesEncrypted
  }
}

/**
 * I need to clone the underlying material.
 * Because when the SDK is done with material, it will zero it out.
 * Plucking off the material and cloning just that and then returning the rest of the response
 * can just be handled in one place.
 * @param response EncryptionResponse|DecryptionResponse
 * @return EncryptionResponse|DecryptionResponse
 */
function cloneResponse<S extends SupportedAlgorithmSuites, R extends EncryptionResponse<S>|DecryptionResponse<S>>(
  response: R
): R {
  const {material} = response
  return {...response, material: cloneMaterial(material)}
}

export interface CachingMaterialsManagerInput<S extends SupportedAlgorithmSuites> extends Readonly<{
  cache: CryptographicMaterialsCache<S>
  backingMaterials: MaterialsManager<S>|Keyring<S>
  partition?: string
  maxBytesEncrypted?: number
  maxMessagesEncrypted?: number
  maxAge?: number
}>{}

export interface CachingMaterialsManagerDecorateInput<S extends SupportedAlgorithmSuites> extends CachingMaterialsManagerInput<S> {
  backingMaterialsManager: MaterialsManager<S>
}

export interface CachingMaterialsManager<S extends SupportedAlgorithmSuites> extends MaterialsManager<S> {
  readonly _partition: string
  readonly _cache: CryptographicMaterialsCache<S>
  readonly _backingMaterialsManager: MaterialsManager<S>
  readonly _maxBytesEncrypted: number
  readonly _maxMessagesEncrypted: number
  readonly _maxAge?: number

  _cacheEntryHasExceededLimits: CacheEntryHasExceededLimits<S>
}

export interface CacheEntryHasExceededLimits<S extends SupportedAlgorithmSuites> {
  (entry: Entry<S>): boolean
}
