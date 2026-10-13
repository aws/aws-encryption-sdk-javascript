// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CryptographicMaterialsCache } from './cryptographic_materials_cache'

/* Concurrent cache misses for the same entry share one request to the backing source.
 * If that request fails, its waiting callers share one retry,
 * so a failing backing source gets one more call, not one per waiting caller.
 * The caching materials manager and the hierarchical keyring both use this.
 */

export const SHARED_REQUESTS = {
  // A request older than this may be stuck, so new callers don't join it.
  inFlightTTL: 1000, // milliseconds
}

// One request to the backing source, and the callers waiting on it.
// `Info` is whatever the request's owner needs to know about each waiting caller.
export interface SharedRequest<M, Info = undefined> {
  startedAt: number
  members: { info: Info; settle: (outcome: SharedOutcome<M>) => void }[]
}

// What a waiting caller gets back:
// - the material
// - the request's error
// - `unshareable`, when the material can't be used for other callers
export type SharedOutcome<M> =
  | { material: M }
  | { error: unknown }
  | { unshareable: true }

/* Requests in progress, by cache and then by cache key.
 * Keyed by cache, so materials managers and keyrings that share a cache also share requests.
 * Each key holds a list, so a stuck request that finishes late removes only itself,
 * not a newer request for the same key.
 */
const inFlight = new WeakMap<
  CryptographicMaterialsCache<any>,
  Map<string, SharedRequest<any, any>[]>
>()

export function inFlightRequestsFor(cache: CryptographicMaterialsCache<any>) {
  return inFlight.get(cache)
}

export function isRecent(request: SharedRequest<any, any>) {
  return Date.now() < request.startedAt + SHARED_REQUESTS.inFlightTTL
}

export function findRequest<R extends SharedRequest<any, any>>(
  cache: CryptographicMaterialsCache<any>,
  key: string,
  canJoin: (request: R) => boolean = isRecent
): R | undefined {
  const requests = inFlight.get(cache)?.get(key) as R[] | undefined
  return requests?.find(canJoin)
}

/* Call this right after findRequest finds nothing, with no await in between.
 * Otherwise callers arriving at the same time each start their own request.
 */
export function startRequest<R extends SharedRequest<any, any>>(
  cache: CryptographicMaterialsCache<any>,
  key: string,
  request: R
): R {
  const byKey =
    inFlight.get(cache) || new Map<string, SharedRequest<any, any>[]>()
  inFlight.set(cache, byKey)
  // A request that hangs never removes itself.
  // This drops it when the next request for this key starts.
  const requests = (byKey.get(key) || []).filter(isRecent)
  requests.push(request)
  byKey.set(key, requests)
  return request
}

export function closeRequest(
  cache: CryptographicMaterialsCache<any>,
  key: string,
  request: SharedRequest<any, any>
) {
  const byKey = inFlight.get(cache)
  const requests = byKey?.get(key)
  if (!byKey || !requests) return
  const index = requests.indexOf(request)
  if (index !== -1) requests.splice(index, 1)
  if (!requests.length) byKey.delete(key)
}

export async function waitOn<M, Info>(
  request: SharedRequest<M, Info>,
  info: Info
): Promise<SharedOutcome<M>> {
  return new Promise<SharedOutcome<M>>((settle) =>
    request.members.push({ info, settle })
  )
}

export function settleMembers<M>(
  request: SharedRequest<M, any>,
  outcome: SharedOutcome<M>
) {
  for (const member of request.members) member.settle(outcome)
}

export interface ShareRequestInput<M> {
  // This caller's copy of the cached material, or undefined on a miss.
  lookUp: () => M | undefined
  fetch: () => Promise<M>
  // Each caller needs its own copy, because the cache zeroes its copy on eviction.
  copy: (material: M) => M
  put: (material: M) => void
}

/* Return the cached material, or wait on another caller's request for the same key,
 * or make the request and share it.
 * If the request this caller waited on fails, it tries once more, and a second failure throws.
 * `retry` is false on that second try.
 */
export async function shareRequest<M>(
  cache: CryptographicMaterialsCache<any>,
  key: string,
  input: ShareRequestInput<M>,
  retry = true
): Promise<M> {
  const cached = input.lookUp()
  if (cached) return cached

  const current = findRequest<SharedRequest<M>>(cache, key)
  if (current) {
    const outcome = await waitOn(current, undefined)
    if ('material' in outcome) return outcome.material
    if ('error' in outcome && !retry) throw outcome.error
    // The caller that made the failed request already removed it,
    // so the first waiting caller to get here starts a new request and the others wait on that one.
    return shareRequest(cache, key, input, false)
  }

  const mine = startRequest<SharedRequest<M>>(cache, key, {
    startedAt: Date.now(),
    members: [],
  })
  let release: SharedOutcome<M> = { unshareable: true }
  try {
    const material = await input.fetch()
    // Copy before put: once cached, an eviction can zero the material.
    const own = input.copy(material)
    for (const member of mine.members) {
      member.settle({ material: input.copy(material) })
    }
    input.put(material)
    return own
  } catch (error) {
    release = { error }
    throw error
  } finally {
    // If the request failed, tell the callers still waiting so they retry once.
    // After a success they already have the material, so this does nothing.
    closeRequest(cache, key, mine)
    settleMembers(mine, release)
  }
}
