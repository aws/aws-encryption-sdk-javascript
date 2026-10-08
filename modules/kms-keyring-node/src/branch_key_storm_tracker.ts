// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NodeAlgorithmSuite } from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'

/* A port of the MPL's StormTracker (StormTracker.dfy).
 * The MPL-based ESDKs use it for the hierarchical keyring's default cache.
 * Times are in milliseconds, and the values match the MPL's DefaultStorm().
 * Read them at call time: tests shorten them.
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

  /* For an entry that is in the cache and not expired. */
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

  /* For an entry that is missing or expired. */
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
   * A failed fetch never calls this, so the entry stays marked
   * and waiters retry after graceInterval instead of at once.
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
 * Two copies of this package in one process each keep their own trackers,
 * so they do not share fetches for the same cache.
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
