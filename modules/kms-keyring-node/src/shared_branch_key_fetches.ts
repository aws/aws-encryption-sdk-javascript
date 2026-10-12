// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeAlgorithmSuite,
  NodeBranchKeyMaterial,
} from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'

/* Concurrent cache misses for the same branch key share one keystore fetch.
 * One caller fetches, and the others wait for its answer.
 * If the shared fetch fails, the waiting callers share one retry,
 * so a failing keystore gets one more call, not one per waiting caller.
 * A caller that already retried gets the error.
 */

// An object, not a constant, so tests can shorten it.
export const SHARED_FETCHES = {
  // A fetch older than this may be stuck, so new callers don't join it.
  graceInterval: 1000, // milliseconds
}

interface SharedFetch {
  startedAt: number
  members: ((outcome: SharedOutcome) => void)[]
}
type SharedOutcome = { material: NodeBranchKeyMaterial } | { error: unknown }

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
 * `retry` is false once this caller has waited on a fetch that failed.
 * Returns a copy only this caller holds.
 */
export async function sharedFetch(
  cmc: CryptographicMaterialsCache<NodeAlgorithmSuite>,
  cacheEntryId: string,
  fetch: () => Promise<NodeBranchKeyMaterial>,
  put: (material: NodeBranchKeyMaterial) => void,
  retry = true
): Promise<NodeBranchKeyMaterial> {
  const byId = sharedFetches.get(cmc) || new Map<string, SharedFetch[]>()
  sharedFetches.set(cmc, byId)
  // Drop this entry's fetches that are too old to join.
  // A fetch that never settles is only ever removed here.
  const fetches = (byId.get(cacheEntryId) || []).filter(isRecent)
  const current = fetches[fetches.length - 1]

  if (current) {
    const outcome = await new Promise<SharedOutcome>((resolve) =>
      current.members.push(resolve)
    )
    if ('material' in outcome) return outcome.material
    if (!retry) throw outcome.error
    // The shared fetch failed. The failed fetch is already closed,
    // so the first waiting caller to resume starts one new fetch and the rest join it.
    return sharedFetch(cmc, cacheEntryId, fetch, put, false)
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

  let failure: SharedOutcome = { error: undefined }
  try {
    const material = await fetch()
    // Copy before put: once cached, an eviction can zero the material's buffer.
    for (const settle of mine.members) {
      settle({ material: deepCopyBranchKeyMaterial(material) })
    }
    put(material)
    return deepCopyBranchKeyMaterial(material)
  } catch (error) {
    failure = { error }
    throw error
  } finally {
    // Close before releasing the waiting callers, so their retry starts a new fetch.
    // Callers that already got the material ignore this.
    close()
    for (const settle of mine.members) settle(failure)
  }
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
