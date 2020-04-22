// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Node has Buffer.compare,
 * but browsers have nothing.
 * This is a simple compare function that is portable.
 * This function is *not* constant time.
 */
export function compare(a: Uint8Array, b: Uint8Array) {
  const length = a.byteLength > b.byteLength ? b.byteLength : a.byteLength

  for (let i = 0; length > i; i += 1) {
    if (a[i] > b[i]) return 1
    if (a[i] < b[i]) return -1
  }

  if (a.byteLength > b.byteLength) return 1
  if (a.byteLength < b.byteLength) return -1

  return 0
}
