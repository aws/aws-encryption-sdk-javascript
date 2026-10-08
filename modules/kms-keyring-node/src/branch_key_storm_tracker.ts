// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NodeAlgorithmSuite } from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'

/* A port of the MPL's StormTracker (StormTracker.dfy),
 * which backs the hierarchical keyring's default cache in every other ESDK.
 * Times are in milliseconds; the values are the MPL's DefaultStorm().
 * Tests shorten them, so read them at call time.
 */
export const STORM_TRACKING = {
  // Within this long of expiring, one caller per graceInterval refreshes the entry.
  gracePeriod: 10 * 1000,
  // After a fetch has run this long, the next caller may start another.
  graceInterval: 1 * 1000,
  // The most keys that can be fetched at once.
  fanOut: 20,
  // A caller that has waited this long fails.
  inFlightTTL: 10 * 1000,
  // How long a waiting caller sleeps before checking the cache again.
  sleepMilli: 20,
}

export type CacheState = 'use' | 'fetch' | 'wait'

export class StormTracker {
  // Cache entry id -> when its current fetch started.
  private readonly inFlight = new Map<string, number>()
  private lastPrune = 0

  /* The entry is in the cache and not expired. */
  checkEntry(id: string, expiresAt: number, now: number): CacheState {
    if (this.fanOutReached(now)) return 'use'
    if (!this.inGracePeriod(expiresAt, now)) return 'use'
    const started = this.inFlight.get(id)
    if (started !== undefined && now < started + STORM_TRACKING.graceInterval) {
      return 'use'
    }
    this.inFlight.set(id, now)
    return 'fetch'
  }

  /* The entry is missing or expired. */
  checkNewEntry(id: string, now: number): CacheState {
    if (this.fanOutReached(now)) return 'wait'
    const started = this.inFlight.get(id)
    if (started !== undefined && now < started + STORM_TRACKING.graceInterval) {
      return 'wait'
    }
    this.inFlight.set(id, now)
    return 'fetch'
  }

  /* Call before putting a fetched entry in the cache.
   * A failed fetch leaves its mark, so waiters retry after graceInterval instead of at once.
   */
  fetched(id: string) {
    this.inFlight.delete(id)
  }

  private inGracePeriod(expiresAt: number, now: number) {
    return expiresAt - STORM_TRACKING.gracePeriod <= now
  }

  private fanOutReached(now: number) {
    this.pruneInFlight(now)
    return this.inFlight.size >= STORM_TRACKING.fanOut
  }

  /* Drops fetches older than inFlightTTL, at most once a second, and only when fanOut is reached. */
  private pruneInFlight(now: number) {
    if (this.inFlight.size < STORM_TRACKING.fanOut) return
    if (now - 1000 < this.lastPrune) return
    this.lastPrune = now
    for (const [id, started] of this.inFlight) {
      if (now >= started + STORM_TRACKING.inFlightTTL) this.inFlight.delete(id)
    }
  }
}

/* One tracker per cache, so keyrings that share a cache also share fetches.
 * The map lives in this module: two copies of this package loaded in one process
 * keep separate trackers for the same cache.
 */
const trackers = new WeakMap<
  CryptographicMaterialsCache<NodeAlgorithmSuite>,
  StormTracker
>()

export function stormTrackerFor(
  cmc: CryptographicMaterialsCache<NodeAlgorithmSuite>
): StormTracker {
  let tracker = trackers.get(cmc)
  if (!tracker) {
    tracker = new StormTracker()
    trackers.set(cmc, tracker)
  }
  return tracker
}

export async function sleep(ms: number) {
  await new Promise((resolve) => setTimeout(resolve, ms))
}
