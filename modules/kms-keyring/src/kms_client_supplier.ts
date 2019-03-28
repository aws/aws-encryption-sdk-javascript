/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import { KMS } from './kms_types/KMS' // eslint-disable-line no-unused-vars
import { KMSConfiguration } from './kms_types/KMSConfiguration' // eslint-disable-line no-unused-vars
import { needs } from '@aws-crypto/material-management'

export interface KMSConstructible<Client extends KMS, Config extends KMSConfiguration> {
  new(config: Config) : Client
}

export interface KmsClientSupplier<Client extends KMS> {
  /* KmsClientProvider is allowed to return undefined if, for example, user wants to exclude particular regions. */
  (region: string): Client|false
}

export function getClient<Client extends KMS, Config extends KMSConfiguration> (
  KMSClient: KMSConstructible<Client, Config>
): KmsClientSupplier<Client> {
  return function getKmsClient (region: string) {
    /* Precondition: region be a string. */
    needs(region && typeof region === 'string', 'A region is required')

    return new KMSClient({ region } as Config)
  }
}

export function limitRegions<Client extends KMS> (
  regions: string[],
  getClient: KmsClientSupplier<Client>
): KmsClientSupplier<Client> {
  /* Precondition: region be a string. */
  needs(regions.every(r => !!r && typeof r === 'string'), 'Can only limit on region strings')

  return (region: string) => {
    if (!regions.includes(region)) return false
    return getClient(region)
  }
}

export function excludeRegions<Client extends KMS> (
  regions: string[],
  getClient: KmsClientSupplier<Client>
): KmsClientSupplier<Client> {
  /* Precondition: region be a string. */
  needs(regions.every(r => !!r && typeof r === 'string'), 'Can only exclude on region strings')

  return (region: string) => {
    if (regions.includes(region)) return false
    return getClient(region)
  }
}

export function cacheClients<Client extends KMS> (
  getClient: KmsClientSupplier<Client>
): KmsClientSupplier<Client> {
  const clientsCache: {[key: string]: Client|false} = {}

  return (region: string) => {
    // Do not cache until KMS has been responded in the given region
    if (!clientsCache.hasOwnProperty(region)) return deferCache(clientsCache, region, getClient(region))
    return clientsCache[region]
  }
}

type KMSOperations = keyof KMS
/* It is possible that a malicious user can attempt a local resource
 * DOS by sending ciphertext with a large number of spurious regions.
 * This will fill the cache with regions and exhaust resources.
 * To avoid this, a call succeeds in contacting KMS.
 * This does *not* mean that this call is successful,
 * only that the region is backed by a functional KMS service.
 */
function deferCache<Client extends KMS> (
  clientsCache: {[key: string]: Client|false},
  region: string,
  client: Client|false
): Client|false {
  /* Check for early return (Postcondition): No client, then I cache false and move on. */
  if (!client) {
    clientsCache[region] = false
    return false
  }
  const { encrypt, decrypt, generateDataKey } = client

  return (<KMSOperations[]>['encrypt', 'decrypt', 'generateDataKey']).reduce(wrapOperation, client)

  /* Wrap each of the operations to cache the client on response */
  function wrapOperation (client: Client, name: KMSOperations): Client {
    type params = Parameters<KMS[typeof name]>
    type retValue = ReturnType<KMS[typeof name]>
    const original = client[name]
    client[name] = function (...args: params): retValue {
      // @ts-ignore (there should be a TypeScript solution for this)
      return original.apply(client, args)
        .then((response: any) => {
          clientsCache[region] = Object.assign(client, { encrypt, decrypt, generateDataKey })
          return response
        })
    }
    return client
  }
}
