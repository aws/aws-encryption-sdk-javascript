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

import LRU from 'lru-cache'
import {
  EncryptionResponse,
  DecryptionResponse,
  SupportedAlgorithmSuites,
  needs,
  isEncryptionMaterial,
  isDecryptionMaterial
} from '@aws-crypto/material-management'

import {
  CryptographicMaterialsCache, // eslint-disable-line no-unused-vars
  Entry, // eslint-disable-line no-unused-vars
  EncryptionResponseEntry, // eslint-disable-line no-unused-vars
  DecryptionResponseEntry // eslint-disable-line no-unused-vars
} from './cryptographic_materials_cache'

export function getLocalCryptographicMaterialsCache<S extends SupportedAlgorithmSuites>(
  maxSize: number
): CryptographicMaterialsCache<S> {
  const cache = new LRU<string, Entry<S>>({
    max: maxSize,
    dispose(_key, value) {
      /* Zero out the unencrypted dataKey, when the material is removed from the cache. */
      value.response.material.zeroUnencryptedDataKey()
    }
  })

  return {
    putEncryptionResponse(
      key: string,
      response: EncryptionResponse<S>,
      plaintextLength: number,
      maxAge?: number
    ) {
      /* Precondition: plaintextLength can not be negative */
      needs(plaintextLength > 0, '')
      /* Precondition: Only cache EncryptionMaterial. */
      needs(isEncryptionMaterial(response.material), '')
      /* Precondition: Only cache EncryptionMaterial that is cacheSafe. */
      needs(response.material.suite.cacheSafe, '')      
      const entry = Object.seal({
        response: Object.freeze(response),
        bytesEncrypted: plaintextLength,
        messagesEncrypted: 1,
        now: Date.now()
      })

      cache.set(key, entry, maxAge)
    },
    putDecryptionResponse(
      key: string,
      response: DecryptionResponse<S>,
      maxAge?: number
    ) {
      /* Precondition: Only cache DecryptionMaterial. */  
      needs(isDecryptionMaterial(response.material), '')
      /* Precondition: Only cache DecryptionMaterial that is cacheSafe. */  
      needs(response.material.suite.cacheSafe, '')
      const entry = Object.seal({
        response: Object.freeze(response),
        bytesEncrypted: 0,
        messagesEncrypted: 0,
        now: Date.now()
      })

      cache.set(key, entry, maxAge)
    },
    getEncryptionResponse(key: string, plaintextLength: number) {
      /* Precondition: plaintextLength can not be negative */
      needs(plaintextLength > 0, '')
      const entry = cache.get(key)
      /* Check for early return (Postcondition): If this key does not have an EncryptionMaterial, return false. */
      if (!entry) return false
      /* Postcondition: Only return EncryptionMaterial. */
      needs(isEncryptionMaterial(entry.response.material), '')

      entry.bytesEncrypted += plaintextLength
      entry.messagesEncrypted += 1

      return <EncryptionResponseEntry<S>>entry
    },
    getDecryptionResponse(key: string){
      const entry = cache.get(key)
      /* Check for early return (Postcondition): If this key does not have a DecryptionMaterial, return false. */
      if (!entry) return false
      /* Postcondition: Only return DecryptionMaterial. */
      needs(isDecryptionMaterial(entry.response.material), '')

      return <DecryptionResponseEntry<S>>entry
    },
    del(key: string) {
      cache.del(key)
    }
  }
}
