// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CryptographicMaterialsCache } from './cryptographic_materials_cache'

/* Concurrent cache misses for the same entry share one request to the backing materials manager.
 * If that request fails, its waiting callers share one retry,
 * so a failing backing materials manager gets one more call, not one per waiting caller.
 */

// An object, not a constant, so tests can shorten it.
export const SHARED_REQUESTS = {
  // A request older than this may be stuck, so new callers don't join it.
  graceInterval: 1000, // milliseconds
}

// Requests in progress, by cache and then by cache key.
// Keyed by cache, so caching materials managers that share a cache also share requests.
export const batchesByCache = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, any[]>
>()
