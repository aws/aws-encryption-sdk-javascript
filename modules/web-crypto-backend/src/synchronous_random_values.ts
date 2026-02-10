// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { supportsSecureRandom } from '@aws-crypto/supports-web-crypto'
import { locateWindow } from '@aws-sdk/util-locate-window'

/* There are uses for a synchronous random source.
 * For example constructors need to be synchronous.
 * The AWS JS SDK uses IRandomValues to have a consistent interface.
 */
export const synchronousRandomValues = generateSynchronousRandomValues(
  locateWindow()
)

export function generateSynchronousRandomValues(
  globalScope: Window
): (byteLength: number) => Uint8Array {
  return function synchronousRandomValues(byteLength: number): Uint8Array {
    if (supportsSecureRandom(globalScope)) {
      return globalScope.crypto.getRandomValues(new Uint8Array(byteLength))
    }

    throw new Error(`Unable to locate a secure random source.`)
  }
}
