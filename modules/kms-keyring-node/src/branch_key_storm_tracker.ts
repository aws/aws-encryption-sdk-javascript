// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeAlgorithmSuite,
  NodeBranchKeyMaterial,
} from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'

/* Shares keystore fetches between concurrent cache misses for the same branch key.
 * KmsHierarchicalKeyRingStormTracking documents both modes.
 * Internal: not exported from the package index.
 */

// Tests shorten these.
export const SHARED_FETCHES = {
  // Default mode: a fetch older than this may be stuck, so new callers make their own.
  graceInterval: 1000, // milliseconds
  // stormTracking mode: how often a waiting caller checks the cache again.
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

// Default mode.

interface SharedFetch {
  startedAt: number
  members: ((outcome: SharedOutcome) => void)[]
}
type SharedOutcome = { material: NodeBranchKeyMaterial } | { failed: true }

/* In-flight fetches by cache, then cache entry id.
 * Keyed by cache so keyrings that share a cache also share fetches.
 * Each fetch is its own object, so a slow fetch that settles late removes only itself,
 * never a newer fetch for the same entry.
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

/* Fetch the branch key materials, or wait for another caller's fetch of the same entry.
 * `fetch` asks the keystore; `put` caches the result.
 * Returns a copy only this caller holds.
 */
export async function sharedFetch(
  cmc: CryptographicMaterialsCache<NodeAlgorithmSuite>,
  cacheEntryId: string,
  fetch: () => Promise<NodeBranchKeyMaterial>,
  put: (material: NodeBranchKeyMaterial) => void
): Promise<NodeBranchKeyMaterial> {
  const byId = sharedFetches.get(cmc) || new Map<string, SharedFetch[]>()
  sharedFetches.set(cmc, byId)
  // Drop fetches nobody can join anymore.
  // This is the only place a fetch that never settles gets forgotten.
  const fetches = (byId.get(cacheEntryId) || []).filter(isRecent)
  const current = fetches[fetches.length - 1]

  if (current) {
    const outcome = await new Promise<SharedOutcome>((resolve) =>
      current.members.push(resolve)
    )
    if ('material' in outcome) return outcome.material
    // The shared fetch failed: make this caller's own fetch, as it would without sharing.
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
  // Copy before put: once cached, an eviction can zero the material's buffer.
  for (const settle of mine.members) {
    settle({ material: deepCopyBranchKeyMaterial(material) })
  }
  put(material)
  return deepCopyBranchKeyMaterial(material)
}

// stormTracking mode: a port of the MPL's StormTracker.dfy.

export type CacheState = 'use' | 'fetch' | 'wait'
// Identifies one fetch, so a late fetch can't be mistaken for a newer one.
export type FetchToken = symbol

/* Tells each caller to use the cached entry, fetch it from the keystore,
 * or wait and check the cache again.
 */
export class StormTracker {
  private readonly inFlight = new Map<
    string,
    { startedAt: number; token: FetchToken }
  >()
  private lastPrune = 0

  // For an unexpired entry: use it, unless it's within gracePeriod of expiring and nobody is refreshing it.
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

  /* For a missing or expired entry: fetch it, unless another caller started fetching it within graceInterval.
   * A failed fetch stays in flight, as in the MPL,
   * so the next fetch waits until the failed one is graceInterval old.
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
   * Only the newest fetch for an entry clears it,
   * so a slow fetch that finishes late can't end a newer one's wait.
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
   * As in the MPL, this runs only when fanOut is reached, at most once a second.
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

/* A copy with its own buffer.
 * The cache zeroes a material's buffer when it evicts it,
 * and callers derive keys from the branch key after getBranchKeyMaterials returns,
 * so handing out the cached buffer lets an eviction zero a key mid-use (#1691).
 */
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
