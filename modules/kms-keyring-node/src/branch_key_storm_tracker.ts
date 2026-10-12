// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeAlgorithmSuite,
  NodeBranchKeyMaterial,
} from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'

/* Concurrent callers that miss the cache for the same branch key share one keystore fetch.
 *
 * By default, sharing never makes a caller fail or wait in a way it would not without sharing:
 * one caller fetches, the others wait for its answer, and if that fetch fails,
 * each waiting caller makes its own fetch. There is no limit on fetches in flight
 * and no timeout for waiting callers.
 *
 * The keyring's stormTracking option instead ports the MPL's StormTracker.dfy,
 * which the other ESDKs use by default for the hierarchical keyring.
 *
 * Internal: not exported from the package index. Tests change these values.
 */
export const SHARED_FETCHES = {
  /* By default: after a fetch has run this long it may be stuck,
   * so new callers stop waiting on it and make their own.
   */
  graceInterval: 1000, // milliseconds
  // With stormTracking: how often a waiting caller checks the cache again.
  sleepMilli: 20,
}

/* The stormTracking settings, in milliseconds. */
export interface StormTrackingSettings {
  gracePeriod: number
  graceInterval: number
  fanOut: number
  inFlightTTL: number
}

/* The MPL's DefaultStorm() settings, in seconds. */
export const STORM_TRACKING_DEFAULTS = Object.freeze({
  gracePeriod: 10,
  graceInterval: 1,
  fanOut: 20,
  inFlightTTL: 10,
})

/* ---------------------------------------------------------------------------
 * Default: share one fetch, and fall back to each caller's own fetch on failure.
 */

interface SharedFetch {
  startedAt: number
  members: ((outcome: SharedOutcome) => void)[]
}
type SharedOutcome = { material: NodeBranchKeyMaterial } | { failed: true }

/* In-flight fetches by cache, then cache entry id.
 * Keyed by cache so keyrings that share a cache also share fetches.
 * Each fetch is its own object, so a slow fetch that settles late
 * only removes itself, never a newer fetch for the same entry.
 */
const sharedFetches = new WeakMap<
  CryptographicMaterialsCache<NodeAlgorithmSuite>,
  Map<string, SharedFetch[]>
>()

export function sharedFetchesFor(
  cmc: CryptographicMaterialsCache<NodeAlgorithmSuite>
) {
  return sharedFetches.get(cmc)
}

function isRecent(fetch: SharedFetch) {
  return Date.now() < fetch.startedAt + SHARED_FETCHES.graceInterval
}

/* Fetch the branch key materials, sharing a fetch another caller already started.
 * `fetch` asks the keystore; `put` caches the result.
 * Returns materials this caller owns: a copy no cache will ever zero.
 */
export async function sharedFetch(
  cmc: CryptographicMaterialsCache<NodeAlgorithmSuite>,
  cacheEntryId: string,
  fetch: () => Promise<NodeBranchKeyMaterial>,
  put: (material: NodeBranchKeyMaterial) => void
): Promise<NodeBranchKeyMaterial> {
  const byId = sharedFetches.get(cmc) || new Map<string, SharedFetch[]>()
  sharedFetches.set(cmc, byId)
  // Drop fetches nobody can join anymore. A fetch that never settles is forgotten here.
  const fetches = (byId.get(cacheEntryId) || []).filter(isRecent)
  const current = fetches[fetches.length - 1]

  if (current) {
    // Another caller is fetching this branch key. Wait for its answer.
    const outcome = await new Promise<SharedOutcome>((resolve) =>
      current.members.push(resolve)
    )
    if ('material' in outcome) return outcome.material
    // That fetch failed. Make this caller's own fetch, as it would without sharing.
    const material = await fetch()
    put(material)
    return deepCopyBranchKeyMaterial(material)
  }

  const mine: SharedFetch = { startedAt: Date.now(), members: [] }
  fetches.push(mine)
  byId.set(cacheEntryId, fetches)
  const close = () => {
    const list = byId.get(cacheEntryId)
    if (!list) return
    const index = list.indexOf(mine)
    if (index !== -1) list.splice(index, 1)
    if (!list.length) byId.delete(cacheEntryId)
  }

  let material: NodeBranchKeyMaterial
  try {
    material = await fetch()
  } catch (error) {
    close()
    for (const settle of mine.members) settle({ failed: true })
    throw error
  }
  close()
  /* Give each waiting caller its own copy before caching the material,
   * because the cache zeroes the material's buffer when it evicts it.
   */
  for (const settle of mine.members) {
    settle({ material: deepCopyBranchKeyMaterial(material) })
  }
  put(material)
  return deepCopyBranchKeyMaterial(material)
}

/* ---------------------------------------------------------------------------
 * With stormTracking: the MPL's StormTracker.
 */

export type CacheState = 'use' | 'fetch' | 'wait'
// Identifies one fetch, so a late fetch can't be mistaken for a newer one.
export type FetchToken = symbol

/* Tells each caller to use the cached entry, fetch it from the keystore,
 * or wait and check the cache again because another caller is fetching it.
 */
export class StormTracker {
  // Cache entries being fetched: when each fetch started, and a token for that fetch.
  private readonly inFlight = new Map<
    string,
    { startedAt: number; token: FetchToken }
  >()
  private lastPrune = 0

  /* For a cached entry that hasn't expired.
   * Use it, unless it's within gracePeriod of expiring and nobody is refreshing it yet.
   */
  checkEntry(
    id: string,
    expiresAt: number,
    now: number,
    settings: StormTrackingSettings
  ): { state: CacheState; token?: FetchToken } {
    if (this.fanOutReached(now, settings)) return { state: 'use' }
    if (now < expiresAt - settings.gracePeriod) return { state: 'use' }
    const current = this.inFlight.get(id)
    if (current && now < current.startedAt + settings.graceInterval) {
      return { state: 'use' }
    }
    return this.start(id, now)
  }

  /* For an entry that's missing or expired.
   * Fetch it, unless another caller started fetching it within the last graceInterval.
   * Like the MPL, a failed fetch stays in flight, so waiting callers fetch again
   * once it is graceInterval old.
   */
  checkNewEntry(
    id: string,
    now: number,
    settings: StormTrackingSettings
  ): { state: CacheState; token?: FetchToken } {
    if (this.fanOutReached(now, settings)) return { state: 'wait' }
    const current = this.inFlight.get(id)
    if (current && now < current.startedAt + settings.graceInterval) {
      return { state: 'wait' }
    }
    return this.start(id, now)
  }

  /* Call when a fetch succeeds.
   * Only the newest fetch for an entry clears it, so a slow fetch that
   * finishes late can't make callers think a newer fetch is done.
   */
  fetched(id: string, token: FetchToken) {
    if (this.inFlight.get(id)?.token === token) this.inFlight.delete(id)
  }

  inFlightCount() {
    return this.inFlight.size
  }

  private start(id: string, now: number) {
    const token = Symbol('fetch')
    this.inFlight.set(id, { startedAt: now, token })
    return { state: 'fetch' as const, token }
  }

  private fanOutReached(now: number, settings: StormTrackingSettings) {
    this.pruneInFlight(now, settings)
    return this.inFlight.size >= settings.fanOut
  }

  /* Forget fetches older than inFlightTTL, so stuck or failed fetches stop counting toward fanOut.
   * Like the MPL, only bother when fanOut is reached, and at most once a second.
   */
  private pruneInFlight(now: number, settings: StormTrackingSettings) {
    if (this.inFlight.size < settings.fanOut) return
    if (now - 1000 < this.lastPrune) return
    this.lastPrune = now
    for (const [id, { startedAt }] of this.inFlight) {
      if (now >= startedAt + settings.inFlightTTL) this.inFlight.delete(id)
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

/* A copy of the materials with its own buffer, which no cache will ever zero. */
export function deepCopyBranchKeyMaterial(
  material: NodeBranchKeyMaterial
): NodeBranchKeyMaterial {
  return new NodeBranchKeyMaterial(
    Buffer.from(material.branchKey()),
    material.branchKeyIdentifier,
    material.branchKeyVersion.toString('utf-8'),
    { ...material.encryptionContext }
  )
}
