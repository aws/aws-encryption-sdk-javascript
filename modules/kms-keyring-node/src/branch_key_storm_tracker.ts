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
 * The grace period (refreshing an entry before it expires) is a keyring option, off by default.
 */
export const STORM_TRACKING = {
  // A fetch running longer than this may be stuck; the next caller fetches again.
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
  // The latest failed fetch for each cache entry, so callers waiting on it get its error.
  private readonly failures = new Map<string, { at: number; error: unknown }>()
  private lastFailurePrune = 0

  /* For a cached entry that hasn't expired.
   * Use it, unless it's within gracePeriod of expiring and nobody is refreshing it yet.
   */
  checkEntry(
    id: string,
    expiresAt: number,
    gracePeriod: number,
    now: number
  ): CacheState {
    if (this.fanOutReached(now)) return 'use'
    if (now < expiresAt - gracePeriod) return 'use'
    const started = this.inFlight.get(id)
    if (started !== undefined && now < started + STORM_TRACKING.graceInterval) {
      return 'use'
    }
    this.inFlight.set(id, now)
    return 'fetch'
  }

  /* For an entry that's missing or expired.
   * Fetch it, unless another caller started fetching it within the last graceInterval.
   */
  checkNewEntry(id: string, now: number): CacheState {
    if (this.fanOutReached(now)) return 'wait'
    const started = this.inFlight.get(id)
    if (started !== undefined && now < started + STORM_TRACKING.graceInterval) {
      return 'wait'
    }
    this.inFlight.set(id, now)
    return 'fetch'
  }

  /* Call when a fetch succeeds. */
  fetched(id: string) {
    this.inFlight.delete(id)
    this.failures.delete(id)
  }

  /* Call when a fetch fails.
   * Callers waiting on it fail with the same error instead of timing out,
   * and the entry stops counting toward fanOut, so the next caller can fetch right away.
   */
  failed(id: string, error: unknown, now: number) {
    this.inFlight.delete(id)
    this.pruneFailures(now)
    this.failures.set(id, { at: now, error })
  }

  /* The error of a fetch for this entry that failed at or after `since`, if any. */
  failureSince(id: string, since: number) {
    const failure = this.failures.get(id)
    return failure && since <= failure.at ? failure : undefined
  }

  private fanOutReached(now: number) {
    this.pruneInFlight(now)
    return this.inFlight.size >= STORM_TRACKING.fanOut
  }

  /* Forget fetches older than inFlightTTL, so stuck fetches stop counting toward fanOut.
   * Like the MPL, only bother when fanOut is reached, and at most once a second.
   */
  private pruneInFlight(now: number) {
    if (this.inFlight.size < STORM_TRACKING.fanOut) return
    if (now - 1000 < this.lastPrune) return
    this.lastPrune = now
    for (const [id, started] of this.inFlight) {
      if (now >= started + STORM_TRACKING.inFlightTTL) this.inFlight.delete(id)
    }
  }

  /* Forget failures older than inFlightTTL. Every caller that could have waited on them has given up.
   * At most once a second.
   */
  private pruneFailures(now: number) {
    if (now - 1000 < this.lastFailurePrune) return
    this.lastFailurePrune = now
    for (const [id, { at }] of this.failures) {
      if (now >= at + STORM_TRACKING.inFlightTTL) this.failures.delete(id)
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
