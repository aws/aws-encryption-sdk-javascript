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

import { fromUtf8 } from '@aws-sdk/util-utf8-browser'
import { getWebCryptoBackend, getNonZeroByteBackend } from '@aws-crypto/web-crypto-backend'
import { concatBuffers } from '@aws-crypto/serialize'

export const sha512 = async (...inputs: (Uint8Array|string)[]) => {
  // Normalize to Uint8Array and squash into a single value.
  const data = concatBuffers(...inputs.map(u => typeof u === 'string' ? fromUtf8(u) : u))
  // Prefer the non-zero byte because this will always be the native implementation.
  const backend = getNonZeroByteBackend(await getWebCryptoBackend())
  // Do the hash
  const ab = await backend.digest('SHA-512', data)
  return new Uint8Array(ab)
}
