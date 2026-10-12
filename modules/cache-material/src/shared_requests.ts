// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CryptographicMaterialsCache } from './cryptographic_materials_cache'

/* Concurrent cache misses for the same entry share one request to the backing materials manager.
 * One caller makes the request, and the others wait for its answer.
 * Sharing must not add failures:
 * if the shared request fails or its material can't be shared, each waiting caller makes its own.
 */

// An object, not a constant, so tests can shorten it.
export const SHARED_REQUESTS = {
  // A request older than this may be stuck, so new callers make their own.
  graceInterval: 1000, // milliseconds == 1 second
}

/* In-flight batches (one request plus its waiting callers) by cache, then cache key.
 * Keyed by cache so caching materials managers that share a cache also share requests.
 * closeBatch removes a cache key once it has no batches, so the map doesn't grow with every key ever used.
 */
export const batchesByCache = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, any[]>
>()
