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

import {
  NodeMaterialsManager, // eslint-disable-line no-unused-vars
  KeyringNode // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import { decryptStream } from './decrypt_stream'

// @ts-ignore
import { finished } from 'readable-stream'
import { Readable, Duplex } from 'stream' // eslint-disable-line no-unused-vars
import { MessageHeader } from '@aws-crypto/serialize' // eslint-disable-line no-unused-vars

export interface DecryptOutput {
  plaintext: Buffer
  messageHeader: MessageHeader
}

export async function decrypt (
  cmm: NodeMaterialsManager|KeyringNode,
  ciphertext: Buffer|Uint8Array|Readable|string,
  encoding?: BufferEncoding
): Promise<DecryptOutput> {
  const stream = decryptStream(cmm)

  const plaintext: Buffer[] = []
  let messageHeader: MessageHeader|false = false
  stream
    .once('MessageHeader', (header: MessageHeader) => { messageHeader = header })
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
    messageHeader
  }
}

function finishedAsync (stream: Duplex) {
  return new Promise((resolve, reject) => {
    finished(stream, (err: Error) => err ? reject(err) : resolve())
  })
}
