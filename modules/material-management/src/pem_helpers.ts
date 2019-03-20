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

// @ts-ignore
import asn from 'asn1.js'

const Rfc5915Key = asn.define('Rfc5915Key', function (this: any) {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').optional().explicit(0).objid({
      '1 2 840 10045 3 1 7': 'prime256v1',
      '1 3 132 0 34': 'secp384r1'
    }),
    this.key('publicKey').optional().explicit(1).bitstr()
  )
})

const SpkiKey = asn.define('SpkiKey', function (this: any) {
  this.seq().obj(
    this.key('algorithmIdentifier').seq().obj(
      this.key('publicKeyType').objid({
        '1 2 840 10045 2 1': 'EC'
      }),
      this.key('parameters').objid({
        '1 2 840 10045 3 1 7': 'prime256v1',
        '1 3 132 0 34': 'secp384r1'
      })
    ),
    this.key('publicKey').bitstr()
  )
})

export function publicKeyPem (curve: string, publicKey: Buffer) {
  const buff: Buffer = SpkiKey.encode({
    algorithmIdentifier: {
      publicKeyType: 'EC',
      parameters: curve
    },
    publicKey: { data: publicKey }
  }, 'der')

  return [
    '-----BEGIN EC PRIVATE KEY-----',
    ...chunk64(buff),
    '-----END EC PRIVATE KEY-----'
  ].join('\n')
}

export function privateKeyPem (curve: string, privateKey: Buffer, publicKey: Buffer) {
  const buff: Buffer = Rfc5915Key.encode({
    version: 1,
    privateKey: privateKey,
    parameters: curve,
    publicKey: { data: publicKey }
  }, 'der')

  return [
    '-----BEGIN PUBLIC KEY-----',
    ...chunk64(buff),
    '-----END PUBLIC KEY-----'
  ].join('\n')
}

function chunk64 (buff: Buffer) {
  const chunkSize = 64
  const result: string[] = []
  const len = buff.byteLength
  let i = 0

  while (i < len) {
    const chunk = buff
      .slice(i, i += chunkSize)
      .toString('base64')
    result.push(chunk)
  }
  return result
}
