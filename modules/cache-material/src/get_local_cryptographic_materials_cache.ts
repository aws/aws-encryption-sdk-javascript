// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SupportedAlgorithmSuites } from '@aws-crypto/material-management'
import { CryptographicMaterialsCache } from './cryptographic_materials_cache'
import { localCryptographicMaterialsCache } from './local_cryptographic_materials_cache'

export function getLocalCryptographicMaterialsCache<
  S extends SupportedAlgorithmSuites
>(
  capacity: number,
  proactiveFrequency: number = 1000 * 60
): CryptographicMaterialsCache<S> {
  return localCryptographicMaterialsCache(
    capacity,
    proactiveFrequency,
    Date.now
  )
}
