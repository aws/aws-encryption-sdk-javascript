import {
  NodeCryptographicMaterialsManager // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import { decryptStream } from './decrypt_stream'

// @ts-ignore
import { finished } from 'readable-stream'
import { Readable } from 'stream' // eslint-disable-line no-unused-vars
import { promisify } from 'util'
import { MessageHeader } from '@aws-crypto/serialize' // eslint-disable-line no-unused-vars
const finishedAsync = promisify(finished)

export interface DecryptOutput {
  plaintext: Buffer
  messageHeader: MessageHeader
}

export async function decrypt (
  cmm: NodeCryptographicMaterialsManager,
  ciphertext: Buffer|Uint8Array|Readable|string,
  encoding?: string
): Promise<DecryptOutput> {
  const stream = decryptStream(cmm)

  const plaintext: Buffer[] = []
  let messageHeader: MessageHeader|false = false
  stream
    .once('MessageHeader', (_header: MessageHeader) => { messageHeader = _header })
    .on('data', (chunk: Buffer) => plaintext.push(chunk))

  // This will check both Uint8Array|Buffer
  if (ciphertext instanceof Uint8Array) {
    stream.end(ciphertext)
  } else if (typeof ciphertext === 'string') {
    stream.end(Buffer.from(ciphertext, encoding))
  } else if (ciphertext.readable) {
    ciphertext.pipe(stream)
  } else {
    throw new Error('Unsupported plaintext')
  }

  await finishedAsync(stream)
  if (!messageHeader) throw new Error('Unknown format')

  return {
    plaintext: Buffer.concat(plaintext),
    messageHeader
  }
}
