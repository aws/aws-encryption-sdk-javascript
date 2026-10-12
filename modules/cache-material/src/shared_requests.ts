// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { needs } from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from './cryptographic_materials_cache'
import type { CachingMaterialsManagerStormTracking } from './caching_cryptographic_materials_decorators'

/* Shares backing requests between concurrent cache misses for the same entry.
 * CachingMaterialsManagerStormTracking documents both modes.
 * Internal: not exported from the package index.
 */

// Tests shorten these.
export const SHARED_REQUESTS = {
  // Default mode: a request older than this may be stuck, so new callers make their own.
  graceInterval: 1000, // milliseconds == 1 second
  // stormTracking mode: how often a caller waiting for fanOut checks again.
  sleepMilli: 20,
}

export interface SharingSettings {
  // false: default mode.
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
 * closeBatch removes a cache key once it has no batches, so the map doesn't grow with every key ever used.
 */
export const batchesByCache = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, any[]>
>()
