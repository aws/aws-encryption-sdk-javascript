// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeAlgorithmSuite,
  NodeBranchKeyMaterial,
} from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from '@aws-crypto/cache-material'

/* Concurrent cache misses for the same branch key share one keystore fetch.
 * One caller fetches, and the others wait for its answer.
 * If that fetch fails, each waiting caller makes its own fetch, as it would without sharing.
 * Internal: not exported from the package index.
 */

// Tests shorten these.
export const SHARED_FETCHES = {
  // A fetch older than this may be stuck, so new callers make their own.
  graceInterval: 1000, // milliseconds
}

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
