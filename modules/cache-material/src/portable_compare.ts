/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Node has Buffer.compare,
 * but browsers have nothing.
 * This is a simple compare function that is portable.
 * This function is *not* constant time.
 */
export function compare (a: Uint8Array, b: Uint8Array) {
  const length = a.byteLength > b.byteLength
    ? b.byteLength
    : a.byteLength

  for (let i = 0; length > i; i += 1) {
    if (a[i] > b[i]) return 1
    if (a[i] < b[i]) return -1
  }

  if (a.byteLength > b.byteLength) return 1
  if (a.byteLength < b.byteLength) return -1

  return 0
}