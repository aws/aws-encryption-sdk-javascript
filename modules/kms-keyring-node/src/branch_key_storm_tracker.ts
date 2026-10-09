// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NodeAlgorithmSuite } from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'

/* Stops concurrent callers from all fetching the same branch key from the keystore.
 * For a cache entry, the tracker tells each caller to
 * use the cached entry, fetch it from the keystore,
 * or wait and check the cache again because another caller is fetching it.
 *
 * Ported from the MPL's StormTracker.dfy,
 * which the other ESDKs use by default for the hierarchical keyring.
 * Timings are in milliseconds, with the MPL's defaults. Tests change them.
 */
export const STORM_TRACKING = {
  // In the last 10 s before an entry expires, one caller refreshes it while the rest keep using it.
  gracePeriod: 10 * 1000,
  // A fetch running longer than this may be stuck or have failed; the next caller fetches again.
  graceInterval: 1 * 1000,
  // At most this many different branch keys are fetched at once; callers for other keys wait.
  fanOut: 20,
  // A caller that has waited this long fails.
  inFlightTTL: 10 * 1000,
  // How often a waiting caller checks the cache.
  sleepMilli: 20,
}

export type CacheState = 'use' | 'fetch' | 'wait'

export class StormTracker {
  // Cache entries being fetched, and when each fetch started.
  private readonly inFlight = new Map<string, number>()
  private lastPrune = 0

  /* For an entry that is cached and not expired. */
  checkEntry(id: string, expiresAt: number, now: number): CacheState {
    // Too many fetches in flight: use the cached entry, even if it is about to expire.
    if (this.fanOutReached(now)) return 'use'
    // Not about to expire: use it.
    if (!this.inGracePeriod(expiresAt, now)) return 'use'
    // About to expire, but another caller is already refreshing it: use it meanwhile.
    const started = this.inFlight.get(id)
    if (started !== undefined && now < started + STORM_TRACKING.graceInterval) {
      return 'use'
    }
    // About to expire and nobody is refreshing it: this caller refreshes it.
    this.inFlight.set(id, now)
    return 'fetch'
  }

  /* For an entry that is missing or expired. */
  checkNewEntry(id: string, now: number): CacheState {
    // Too many fetches in flight: wait for one to finish.
    if (this.fanOutReached(now)) return 'wait'
    // Another caller started fetching it less than graceInterval ago: wait for that fetch.
    const started = this.inFlight.get(id)
    if (started !== undefined && now < started + STORM_TRACKING.graceInterval) {
      return 'wait'
    }
    // Nobody is fetching it, or that fetch may be stuck or have failed: this caller fetches it.
    this.inFlight.set(id, now)
    return 'fetch'
  }

  /* Call when a fetch succeeds.
   * A failed fetch does not call this, so waiting callers fetch again after graceInterval,
   * one at a time, instead of all at once.
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

  /* Forget fetches older than inFlightTTL, so stuck fetches stop counting toward fanOut. */
  private pruneInFlight(now: number) {
    // As in the MPL, only when fanOut is reached, and at most once a second.
    if (this.inFlight.size < STORM_TRACKING.fanOut) return
    if (now - 1000 < this.lastPrune) return
    this.lastPrune = now
    for (const [id, started] of this.inFlight) {
      if (now >= started + STORM_TRACKING.inFlightTTL) this.inFlight.delete(id)
    }
  }
}

/* One tracker per cache, so keyrings that share a cache also share fetches. */
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
