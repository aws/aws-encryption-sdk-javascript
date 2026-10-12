// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CryptographicMaterialsCache } from './cryptographic_materials_cache'

/* Concurrent cache misses for the same entry share one request to the backing materials manager.
 * One caller makes the request, and the others wait for its answer.
 */

export const SHARED_REQUESTS = {
  // A request older than this may be stuck. New callers won't join it.
  graceInterval: 1000, // milliseconds == 1 second
}

/* Index in-flight batches by cache so caching materials managers that share a cache also share requests.
 */
export const batchesByCache = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, any[]>
>()
