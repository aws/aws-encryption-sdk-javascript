// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { locateWindow } from '@aws-sdk/util-locate-window'
import { webCryptoBackendFactory } from './backend-factory'

const { getWebCryptoBackend, configureFallback } = webCryptoBackendFactory(
  locateWindow()
)
export { getWebCryptoBackend, configureFallback }

export {
  getNonZeroByteBackend,
  getZeroByteSubtle,
  isFullSupportWebCryptoBackend,
  WebCryptoBackend,
  FullSupportWebCryptoBackend,
  MixedSupportWebCryptoBackend,
} from './backend-factory'

export { synchronousRandomValues } from './synchronous_random_values'
