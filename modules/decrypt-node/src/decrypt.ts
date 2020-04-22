// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeMaterialsManager,
  KeyringNode,
} from '@aws-crypto/material-management-node'
import { decryptStream } from './decrypt_stream'

// @ts-ignore
import { finished } from 'readable-stream'
import { Readable, Duplex } from 'stream'
import { MessageHeader } from '@aws-crypto/serialize'

export interface DecryptOutput {
  plaintext: Buffer
  messageHeader: MessageHeader
}

export interface DecryptOptions {
  encoding?: BufferEncoding
  maxBodySize?: number
}

export async function decrypt(
  cmm: NodeMaterialsManager | KeyringNode,
  ciphertext: Buffer | Uint8Array | Readable | string | NodeJS.ReadableStream,
  { encoding, maxBodySize }: DecryptOptions = {}
): Promise<DecryptOutput> {
  const stream = decryptStream(cmm, { maxBodySize })

  const plaintext: Buffer[] = []
  let messageHeader: MessageHeader | false = false
  stream
    .once('MessageHeader', (header: MessageHeader) => {
      messageHeader = header
    })
    .on('data', (chunk: Buffer) => plaintext.push(chunk))

  // This will check both Uint8Array|Buffer
  if (ciphertext instanceof Uint8Array) {
    stream.end(ciphertext)
  } else if (typeof ciphertext === 'string') {
    stream.end(Buffer.from(ciphertext, encoding))
  } else if (ciphertext.readable) {
    ciphertext.pipe(stream)
  } else {
    throw new Error('Unsupported ciphertext format')
  }

  await finishedAsync(stream)
  if (!messageHeader) throw new Error('Unknown format')

  return {
    plaintext: Buffer.concat(plaintext),
    messageHeader,
  }
}

async function finishedAsync(stream: Duplex) {
  return new Promise((resolve, reject) => {
    finished(stream, (err: Error) => (err ? reject(err) : resolve()))
  })
}
