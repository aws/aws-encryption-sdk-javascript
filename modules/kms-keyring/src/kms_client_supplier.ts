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
  (region: string): Client|undefined
}

export function getClient<Client extends KMS, Config extends KMSConfiguration> (KMSClient: KMSConstructible<Client, Config>): KmsClientSupplier<Client> {
  return function getKmsClient (region: string) {
    /* Precondition: region be a string. */
    needs(region && typeof region === 'string', 'A region is required')

    return new KMSClient({ region } as Config)
  }
}

export function limitRegions<Client extends KMS> (regions: string[], getClient: KmsClientSupplier<Client>): KmsClientSupplier<Client> {
  /* Precondition: region be a string. */
  needs(regions.every(r => !!r && typeof r == 'string'), 'Can only limit on region strings')

  return (region: string) => {
    if (!regions.includes(region)) return
    return getClient(region)
  }
}

export function excludeRegions<Client extends KMS> (regions: string[], getClient: KmsClientSupplier<Client>): KmsClientSupplier<Client> {
  /* Precondition: region be a string. */
  needs(regions.every(r => !!r && typeof r === 'string'), 'Can only exclude on region strings')

  return (region: string) => {
    if (regions.includes(region)) return
    return getClient(region)
  }
}

export function cacheClients<Client extends KMS> (getClient: KmsClientSupplier<Client>): KmsClientSupplier<Client> {
  const clientsCache: {[key: string]: Client|undefined} = {}

  return (region: string) => {
    // undefined is a acceptable response...
    if (!clientsCache.hasOwnProperty(region)) clientsCache[region] = getClient(region)
    return clientsCache[region]
  }
}
