// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* Before Node.js v11 the crypto module did not support
 * a method to PEM format a ECDH key.  It has always supported
 * producing such keys: `crypto.createECDH`.  But formatting
 * these keys as a PEM for use in `crypto.Sign` and
 * `crypto.Verify` has not been possible in native `crypto`.
 * As Node.js v6, v8, and v10 reach end of life, this code
 * can be deleted.
 */

// @ts-ignore
import asn from 'asn1.js'

const Rfc5915Key = asn.define('Rfc5915Key', function (this: any) {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').optional().explicit(0).objid({
      '1 2 840 10045 3 1 7': 'prime256v1',
      '1 3 132 0 34': 'secp384r1',
    }),
    this.key('publicKey').optional().explicit(1).bitstr()
  )
})

const SpkiKey = asn.define('SpkiKey', function (this: any) {
  this.seq().obj(
    this.key('algorithmIdentifier')
      .seq()
      .obj(
        this.key('publicKeyType').objid({
          '1 2 840 10045 2 1': 'EC',
        }),
        this.key('parameters').objid({
          '1 2 840 10045 3 1 7': 'prime256v1',
          '1 3 132 0 34': 'secp384r1',
        })
      ),
    this.key('publicKey').bitstr()
  )
})

export function publicKeyPem(curve: string, publicKey: Buffer) {
  const buff: Buffer = SpkiKey.encode(
    {
      algorithmIdentifier: {
        publicKeyType: 'EC',
        parameters: curve,
      },
      publicKey: { data: publicKey },
    },
    'der'
  )

  return [
    '-----BEGIN PUBLIC KEY-----',
    ...chunk64(buff),
    '-----END PUBLIC KEY-----',
    '',
  ].join('\n')
}

export function privateKeyPem(
  curve: string,
  privateKey: Buffer,
  publicKey: Buffer
) {
  const buff: Buffer = Rfc5915Key.encode(
    {
      version: 1,
      privateKey: privateKey,
      parameters: curve,
      publicKey: { data: publicKey },
    },
    'der'
  )

  return [
    '-----BEGIN EC PRIVATE KEY-----',
    ...chunk64(buff),
    '-----END EC PRIVATE KEY-----',
    '',
  ].join('\n')
}

export function chunk64(buff: Buffer) {
  const chunkSize = 64
  const str = buff.toString('base64')
  const numChunks = Math.ceil(str.length / chunkSize)
  const chunks: string[] = new Array(numChunks)

  for (let i = 0, o = 0; i < numChunks; ++i, o += chunkSize) {
    chunks[i] = str.substr(o, chunkSize)
  }

  return chunks
}
