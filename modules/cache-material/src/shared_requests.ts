// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { needs } from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from './cryptographic_materials_cache'
import type { CachingMaterialsManagerStormTracking } from './caching_cryptographic_materials_decorators'

/* If many encrypt or decrypt calls use the cache at the same time,
 * cache misses for the same entry share one request to the backing materials manager.
 * One caller asks the backing materials manager, and the rest wait for its answer.
 *
 * Internal: not exported from the package index. Tests change these values.
 */
export const SHARED_REQUESTS = {
  /* Without storm tracking: after a request has run this long, it may be stuck,
   * so new callers stop waiting on it and make their own.
   */
  graceInterval: 1000, // milliseconds == 1 second
  // With storm tracking: how often a caller waiting for fanOut to free up checks again.
  sleepMilli: 20,
}

/* How a caching materials manager shares requests. */
export interface SharingSettings {
  // false: the defaults described on CachingMaterialsManagerStormTracking.
  stormTracking: boolean
  graceInterval: number
  fanOut: number
  inFlightTTL: number
}

export const STORM_TRACKING_DEFAULTS = Object.freeze({
  graceInterval: 1000,
  fanOut: 20,
  inFlightTTL: 10 * 1000,
})

export function resolveStormTracking(
  stormTracking?: CachingMaterialsManagerStormTracking
): Readonly<SharingSettings> | undefined {
  if (stormTracking === undefined) return undefined
  /* Precondition: stormTracking must be an object. */
  needs(
    stormTracking && typeof stormTracking === 'object',
    'stormTracking must be an object.'
  )
  const {
    graceInterval = STORM_TRACKING_DEFAULTS.graceInterval,
    fanOut = STORM_TRACKING_DEFAULTS.fanOut,
    inFlightTTL = STORM_TRACKING_DEFAULTS.inFlightTTL,
  } = stormTracking
  /* Precondition: stormTracking.graceInterval must be a positive number. */
  needs(
    isPositive(graceInterval),
    'stormTracking.graceInterval must be a positive number.'
  )
  /* Precondition: stormTracking.inFlightTTL must be a positive number. */
  needs(
    isPositive(inFlightTTL),
    'stormTracking.inFlightTTL must be a positive number.'
  )
  /* Precondition: stormTracking.fanOut must be a positive integer. */
  needs(
    Number.isSafeInteger(fanOut) && fanOut > 0,
    'stormTracking.fanOut must be a positive integer.'
  )
  /* Precondition: stormTracking.graceInterval must not exceed stormTracking.inFlightTTL. */
  needs(
    graceInterval <= inFlightTTL,
    'stormTracking.graceInterval must not exceed stormTracking.inFlightTTL.'
  )
  return Object.freeze({
    stormTracking: true,
    graceInterval,
    fanOut,
    inFlightTTL,
  })
}

function isPositive(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0
}

/* In-flight batches (one request plus its waiting callers) by cache, then cache key.
 * Keyed by cache so caching materials managers that share a cache also share requests.
 * A cache key is removed once it has no batches, so this does not grow with every key ever used.
 */
export const batchesByCache = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, any[]>
>()
