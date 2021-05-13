// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { isMsWindow } from '@aws-crypto/ie11-detection'
import {
  supportsWebCrypto,
  supportsSubtleCrypto,
  supportsZeroByteGCM,
} from '@aws-crypto/supports-web-crypto'
import { generateSynchronousRandomValues } from './synchronous_random_values'
import promisifyMsSubtleCrypto from './promisify-ms-crypto'

type MaybeSubtleCrypto = SubtleCrypto | false
export type WebCryptoBackend =
  | FullSupportWebCryptoBackend
  | MixedSupportWebCryptoBackend
export type FullSupportWebCryptoBackend = {
  subtle: SubtleCrypto
  randomValues: (byteLength: number) => Uint8Array
}
export type MixedSupportWebCryptoBackend = {
  zeroByteSubtle: SubtleCrypto
  nonZeroByteSubtle: SubtleCrypto
  randomValues: (byteLength: number) => Uint8Array
}

export function webCryptoBackendFactory(window: Window) {
  const fallbackRequiredPromise = windowRequiresFallback(window)
  const randomValues = generateSynchronousRandomValues(window)
  let webCryptoFallbackPromise: Promise<SubtleCrypto> | false = false

  return { getWebCryptoBackend, configureFallback }

  async function getWebCryptoBackend(): Promise<WebCryptoBackend> {
    /* Precondition: Access to a secure random source is required. */
    try {
      randomValues(1)
    } catch (ex) {
      throw new Error('No supported secure random')
    }

    const fallbackRequired = await fallbackRequiredPromise
    const subtle = pluckSubtleCrypto(window)
    const webCryptoFallback = await webCryptoFallbackPromise

    /* Postcondition: If a a subtle backend exists and a fallback is required, one must be configured.
     * In this case the subtle backend does not support zero byte GCM operations.
     */
    if (subtle && fallbackRequired && !webCryptoFallback) {
      throw new Error(
        'A Fallback is required for zero byte AES-GCM operations.'
      )
    }

    /* Postcondition: If no SubtleCrypto exists, a fallback must configured. */
    if (!subtle && !webCryptoFallback) {
      throw new Error(
        'A Fallback is required because no subtle backend exists.'
      )
    }

    if (!fallbackRequired && subtle) {
      return { subtle, randomValues }
    }

    if (fallbackRequired && subtle && webCryptoFallback) {
      return {
        nonZeroByteSubtle: subtle,
        randomValues,
        zeroByteSubtle: webCryptoFallback,
      }
    }

    if (fallbackRequired && !subtle && webCryptoFallback) {
      return { subtle: webCryptoFallback, randomValues }
    }

    throw new Error('unknown error')
  }

  async function configureFallback(fallback: SubtleCrypto) {
    const fallbackRequired = await fallbackRequiredPromise
    /* Precondition: If a fallback is not required, do not configure one. */
    if (!fallbackRequired) {
      return
    }

    /* Precondition: Can not reconfigure fallback. */
    if (webCryptoFallbackPromise)
      throw new Error('Fallback reconfiguration denied')

    /* Precondition: Fallback must look like it supports the required operations. */
    if (!supportsSubtleCrypto(fallback))
      throw new Error('Fallback does not support WebCrypto')

    // This if to lock the fallback.
    // when using the fallback, it is simpler
    // for the customer to not await the success
    // of configuration so we handle it for them
    // I still return in case they want to await
    webCryptoFallbackPromise = supportsZeroByteGCM(fallback).then(
      (zeroByteGCMSupport) => {
        /* Postcondition: The fallback must specifically support ZeroByteGCM. */
        if (!zeroByteGCMSupport)
          throw new Error('Fallback does not support zero byte AES-GCM')
        return fallback
      }
    )
    return webCryptoFallbackPromise
  }
}

export function getNonZeroByteBackend(backend: WebCryptoBackend | false) {
  /* Precondition: A backend must be passed to get a non zero byte backend. */
  if (!backend) throw new Error('No supported backend.')
  return (
    (backend as FullSupportWebCryptoBackend).subtle ||
    (backend as MixedSupportWebCryptoBackend).nonZeroByteSubtle
  )
}

export function getZeroByteSubtle(backend: WebCryptoBackend | false) {
  /* Precondition: A backend must be passed to get a zero byte backend. */
  if (!backend) throw new Error('No supported backend.')
  return (
    (backend as FullSupportWebCryptoBackend).subtle ||
    (backend as MixedSupportWebCryptoBackend).zeroByteSubtle
  )
}

export async function windowRequiresFallback(window: Window) {
  const subtle = pluckSubtleCrypto(window)

  if (!subtle) return true
  const zeroByteSupport = await supportsZeroByteGCM(subtle)
  return !zeroByteSupport
}

export function pluckSubtleCrypto(window: Window): MaybeSubtleCrypto {
  // if needed webkitSubtle check should be added here
  // see: https://webkit.org/blog/7790/update-on-web-cryptography/
  if (supportsWebCrypto(window)) return window.crypto.subtle
  if (isMsWindow(window)) return promisifyMsSubtleCrypto(window.msCrypto.subtle)
  return false
}

export function isFullSupportWebCryptoBackend(
  backend: WebCryptoBackend
): backend is FullSupportWebCryptoBackend {
  return !!(backend as FullSupportWebCryptoBackend).subtle
}
