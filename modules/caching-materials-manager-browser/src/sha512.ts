// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { fromUtf8 } from '@aws-sdk/util-utf8-browser'
import {
  getWebCryptoBackend,
  getNonZeroByteBackend,
} from '@aws-crypto/web-crypto-backend'
import { concatBuffers } from '@aws-crypto/serialize'

export const sha512 = async (...inputs: (Uint8Array | string)[]) => {
  // Normalize to Uint8Array and squash into a single value.
  const data = concatBuffers(
    ...inputs.map((u) => (typeof u === 'string' ? fromUtf8(u) : u))
  )
  // Prefer the non-zero byte because this will always be the native implementation.
  const backend = getNonZeroByteBackend(await getWebCryptoBackend())
  // Do the hash
  const ab = await backend.digest('SHA-512', data)
  return new Uint8Array(ab)
}
