// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { toBase64 } from '@aws-sdk/util-base64-browser'

export function bytes2JWK(rawKeyBytes: Uint8Array): JsonWebKey {
  // See https://tools.ietf.org/html/rfc7515#appendix-C Base64url Encoding
  const base64 = toBase64(rawKeyBytes)
  const base64Url = base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
  return {
    kty: 'oct',
    k: base64Url,
  }
}
