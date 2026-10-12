// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeAlgorithmSuite,
  NodeBranchKeyMaterial,
} from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'

/* Concurrent cache misses for the same branch key share one keystore fetch.
 * If that fetch fails, its waiting callers share one retry,
 * so a failing keystore gets one more call, not one per waiting caller.
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

/* Keyed by cache, so keyrings that share a cache also share fetches.
 * Each entry id holds a list, so a stale fetch that settles late removes only itself,
 * not a newer fetch for the same entry.
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

/* Fetch the branch key materials, or wait on another caller's fetch of the same entry.
 * Returns a copy only this caller holds.
 * A caller that waited on a failed fetch gets one more attempt, with `retry` false.
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
  // A fetch that never settles is only removed here, once a newer one starts for the same entry.
  const fetches = (byId.get(cacheEntryId) || []).filter(isRecent)
  const current = fetches[fetches.length - 1]

  if (current) {
    const outcome = await new Promise<SharedOutcome>((resolve) =>
      current.members.push(resolve)
    )
    if ('material' in outcome) return outcome.material
    if (!retry) throw outcome.error
    // The failed fetch closed before its waiting callers resumed,
    // so the first one to resume starts the retry and the rest join it.
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
    // Close before settling, so a waiting caller's retry starts a new fetch
    // instead of rejoining this one.
    // Callers that already got the material ignore this second settle.
    close()
    for (const settle of mine.members) settle(failure)
  }
}

/* The cache zeroes a material's buffer when it evicts it.
 * Callers derive keys from the branch key after getBranchKeyMaterials returns,
 * so they need their own buffer, or an eviction can zero the key mid-use (#1691).
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
