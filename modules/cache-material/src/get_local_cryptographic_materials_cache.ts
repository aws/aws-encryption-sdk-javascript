// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import LRU from 'lru-cache'
import {
  EncryptionMaterial,
  DecryptionMaterial,
  SupportedAlgorithmSuites,
  needs,
  isEncryptionMaterial,
  isDecryptionMaterial,
} from '@aws-crypto/material-management'

import {
  CryptographicMaterialsCache,
  Entry,
  EncryptionMaterialEntry,
  DecryptionMaterialEntry,
} from './cryptographic_materials_cache'

export function getLocalCryptographicMaterialsCache<
  S extends SupportedAlgorithmSuites
>(
  capacity: number,
  proactiveFrequency: number = 1000 * 60
): CryptographicMaterialsCache<S> {
  const cache = new LRU<string, Entry<S>>({
    max: capacity,
    dispose(_key, value) {
      /* Zero out the unencrypted dataKey, when the material is removed from the cache. */
      value.response.zeroUnencryptedDataKey()
    },
  })

  /* It is not a guarantee that the last item in the LRU will be the Oldest Item.
   * But such degenerative cases are not my concern.
   * The LRU will not return things that are too old,
   * so all this is just to try and proactively dispose material.
   *
   * To be clear, as an example say I add 9 items at T=0.
   * If the MaxAge is 60 minutes, and at T=59 I add a 10th item.
   * Then get each of the other 9 items.
   * Now, at T=60, `mayEvictTail` will check the age of the tail
   * and not evict it because the item has not aged out.
   * If there is no get activity,
   * it will take until T=120 before I again begin evicting items.
   */
  ;(function proactivelyTryAndEvictTail() {
    const timeout = setTimeout(() => {
      mayEvictTail()
      proactivelyTryAndEvictTail()
    }, proactiveFrequency)
    /* In Node.js the event loop will _only_ exit if there are no outstanding events.
     * This means that if I did nothing the event loop would *always* be blocked.
     * This is unfortunate and very bad for things like Lambda.
     * So, I tell Node.js to not wait for this timer.
     * See: https://nodejs.org/api/timers.html#timers_timeout_unref
     */
    // @ts-ignore
    timeout.unref && timeout.unref()
  })()

  return {
    putEncryptionMaterial(
      key: string,
      material: EncryptionMaterial<S>,
      plaintextLength: number,
      maxAge?: number
    ) {
      /* Precondition: putEncryptionMaterial plaintextLength can not be negative. */
      needs(plaintextLength >= 0, 'Malformed plaintextLength')
      /* Precondition: Only cache EncryptionMaterial. */
      needs(isEncryptionMaterial(material), 'Malformed response.')
      /* Precondition: Only cache EncryptionMaterial that is cacheSafe. */
      needs(material.suite.cacheSafe, 'Can not cache non-cache safe material')
      const entry = Object.seal({
        response: material,
        bytesEncrypted: plaintextLength,
        messagesEncrypted: 1,
        now: Date.now(),
      })

      cache.set(key, entry, maxAge)
    },
    putDecryptionMaterial(
      key: string,
      material: DecryptionMaterial<S>,
      maxAge?: number
    ) {
      /* Precondition: Only cache DecryptionMaterial. */
      needs(isDecryptionMaterial(material), 'Malformed response.')
      /* Precondition: Only cache DecryptionMaterial that is cacheSafe. */
      needs(material.suite.cacheSafe, 'Can not cache non-cache safe material')
      const entry = Object.seal({
        response: material,
        bytesEncrypted: 0,
        messagesEncrypted: 0,
        now: Date.now(),
      })

      cache.set(key, entry, maxAge)
    },
    getEncryptionMaterial(key: string, plaintextLength: number) {
      /* Precondition: plaintextLength can not be negative. */
      needs(plaintextLength >= 0, 'Malformed plaintextLength')
      const entry = cache.get(key)
      /* Check for early return (Postcondition): If this key does not have an EncryptionMaterial, return false. */
      if (!entry) return false
      /* Postcondition: Only return EncryptionMaterial. */
      needs(isEncryptionMaterial(entry.response), 'Malformed response.')

      entry.bytesEncrypted += plaintextLength
      entry.messagesEncrypted += 1

      return entry as EncryptionMaterialEntry<S>
    },
    getDecryptionMaterial(key: string) {
      const entry = cache.get(key)
      /* Check for early return (Postcondition): If this key does not have a DecryptionMaterial, return false. */
      if (!entry) return false
      /* Postcondition: Only return DecryptionMaterial. */
      needs(isDecryptionMaterial(entry.response), 'Malformed response.')

      return entry as DecryptionMaterialEntry<S>
    },
    del(key: string) {
      cache.del(key)
    },
  }

  function mayEvictTail() {
    // @ts-ignore
    const { tail } = cache.dumpLru()
    /* Check for early return (Postcondition) UNTESTED: If there is no tail, then the cache is empty. */
    if (!tail) return
    /* The underlying Yallist tail Node has a `value`.
     * This value is a lru-cache Entry and has a `key`.
     */
    const { key } = tail.value
    // Peek will evict, but not update the "recently used"-ness of the key.
    cache.peek(key)
  }
}
