// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CryptographicMaterialsCache } from './cryptographic_materials_cache'

/* If many encrypt or decrypt calls use the cache at the same time,
 * cache misses for the same entry share one request to the backing materials manager.
 * One caller asks the backing materials manager, and the rest wait for its answer.
 * These limits stop a slow or stuck request from holding up any waiting callers.
 *
 * Internal: not exported from the package index. Tests change these values.
 */
export const SHARED_REQUESTS = {
  // After a request has run this long, new callers stop waiting on it and make their own.
  graceInterval: 1000, // milliseconds == 1 second
  // A caller that has waited this long fails.
  inFlightTTL: 10 * 1000, // milliseconds == 10 seconds
}

/* In-flight batches (one request plus its waiting callers) by cache, then cache key.
 * Keyed by cache so caching materials managers that share a cache also share requests.
 * A cache key is removed once it has no batches, so this does not grow with every key ever used.
 */
export const batchesByCache = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, any[]>
>()
