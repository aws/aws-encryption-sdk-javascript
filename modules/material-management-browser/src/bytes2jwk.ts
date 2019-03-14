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

import { toBase64 } from '@aws-sdk/util-base64-browser'

export function bytes2JWK (rawKeyBytes: Uint8Array): JsonWebKey {
  // See https://tools.ietf.org/html/rfc7515 Base64url Encoding
  const base64 = toBase64(rawKeyBytes)
  const base64Url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  return {
    kty: 'oct',
    k: base64Url
  }
}
