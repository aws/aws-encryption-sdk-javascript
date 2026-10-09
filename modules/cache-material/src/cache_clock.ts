// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* The time source for a cache's entries, and for the caching CMMs that check their age.
 * A cache built with getLocalCryptographicMaterialsCache uses Date.now.
 * The ESDK test server builds caches with a clock it can move forward,
 * so tests can expire entries without waiting.
 * This module is not exported from the package index.
 */
import { CryptographicMaterialsCache } from './cryptographic_materials_cache'

export type Clock = () => number

const clocks = new WeakMap<CryptographicMaterialsCache<any>, Clock>()

export function setClock(
  cache: CryptographicMaterialsCache<any>,
  clock: Clock
): void {
  clocks.set(cache, clock)
}

/* A cache from another implementation has no registered clock, so it gets Date.now. */
export function clockFor(cache: CryptographicMaterialsCache<any>): Clock {
  return clocks.get(cache) || Date.now
}
