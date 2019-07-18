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

import { needs } from '@aws-crypto/material-management'
import {
  AwsEsdkKMSInterface // eslint-disable-line no-unused-vars
} from './kms_types'

interface KMSConstructibleNonOption<Client extends AwsEsdkKMSInterface, Config> {
  new(config: Config) : Client
}

interface KMSConstructibleOption<Client extends AwsEsdkKMSInterface, Config> {
  new(config?: Config) : Client
}

export type KMSConstructible<Client extends AwsEsdkKMSInterface, Config> = KMSConstructibleNonOption<Client, Config> | KMSConstructibleOption<Client, Config>

export interface KmsClientSupplier<Client extends AwsEsdkKMSInterface> {
  /* KmsClientProvider is allowed to return undefined if, for example, user wants to exclude particular regions. */
  (region: string): Client | false
}

export function getClient<Client extends AwsEsdkKMSInterface, Config> (
  KMSClient: KMSConstructible<Client, Config>,
  defaultConfig?: Config
): KmsClientSupplier<Client> {
  return function getKmsClient (region: string) {
    /* a KMS alias is supported.  These do not have a region
     * in this case, the Encryption SDK should find the default region
     * or the default region needs to be supplied to this function
     */
    const config = { ...defaultConfig, region } as Config
    const client = new KMSClient(config)

    /* Postcondition: A region must be configured.
     * The AWS SDK has a process for determining the default region.
     * A user can configure a default region by setting it in `defaultConfig`
     * But KMS requires a region to operate.
     */
    // @ts-ignore the V3 client has set the config to protected, reasonable, but I need to know...
    needs(client.config.region, 'A region is required')
    return client
  }
}

export function limitRegions<Client extends AwsEsdkKMSInterface> (
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

export function excludeRegions<Client extends AwsEsdkKMSInterface> (
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

export function cacheClients<Client extends AwsEsdkKMSInterface> (
  getClient: KmsClientSupplier<Client>
): KmsClientSupplier<Client> {
  const clientsCache: {[key: string]: Client|false} = {}

  return (region: string) => {
    // Do not cache until KMS has been responded in the given region
    if (!clientsCache.hasOwnProperty(region)) return deferCache(clientsCache, region, getClient(region))
    return clientsCache[region]
  }
}

/* It is possible that a malicious user can attempt a local resource
 * DOS by sending ciphertext with a large number of spurious regions.
 * This will fill the cache with regions and exhaust resources.
 * To avoid this, a call succeeds in contacting KMS.
 * This does *not* mean that this call is successful,
 * only that the region is backed by a functional KMS service.
 */
function deferCache<Client extends AwsEsdkKMSInterface> (
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

  return (<(keyof AwsEsdkKMSInterface)[]>['encrypt', 'decrypt', 'generateDataKey']).reduce(wrapOperation, client)

  /* Wrap each of the operations to cache the client on response */
  function wrapOperation (client: Client, name: keyof AwsEsdkKMSInterface): Client {
    const original = client[name]
    client[name] = function wrappedOperation (this: Client, args: any): Promise<any> {
      // @ts-ignore (there should be a TypeScript solution for this)
      const v2vsV3Response = original.call(client, args)
      const v2vsV3Promise = 'promise' in v2vsV3Response
        ? v2vsV3Response.promise()
        : v2vsV3Response
      return v2vsV3Promise
        .then((response: any) => {
          clientsCache[region] = Object.assign(client, { encrypt, decrypt, generateDataKey })
          return response
        })
        .catch((e: any) => {
          /* Errors from a KMS contact mean that the region is "live".
           * As such the client can be cached because the problem is not with the client per se,
           * but with the request made.
           */
          if (e.$metadata && e.$metadata.httpStatusCode) {
            clientsCache[region] = Object.assign(client, { encrypt, decrypt, generateDataKey })
          }
          // The request was not successful
          return Promise.reject(e)
        })
    }
    return client
  }
}
