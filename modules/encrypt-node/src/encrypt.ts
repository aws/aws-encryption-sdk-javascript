import {
  NodeCryptographicMaterialsManager // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import {
  encryptStream,
  EncryptStreamInput // eslint-disable-line no-unused-vars
} from './encrypt_stream'

// @ts-ignore
import { finished } from 'readable-stream'
import { Readable } from 'stream' // eslint-disable-line no-unused-vars
import { Duplexify } from 'duplexify' // eslint-disable-line no-unused-vars
import { MessageHeader } from '@aws-crypto/serialize' // eslint-disable-line no-unused-vars

interface EncryptInput extends EncryptStreamInput {
  encoding?: string
}

export interface EncryptOutput {
  ciphertext: Buffer
  messageHeader: MessageHeader
}

export async function encrypt (
  cmm: NodeCryptographicMaterialsManager,
  plaintext: Buffer|Uint8Array|Readable|string,
  op: EncryptInput = {}
): Promise<EncryptOutput> {
  const stream = encryptStream(cmm, op)
  const { encoding } = op

  const ciphertext: Buffer[] = []
  const messageHeader: MessageHeader|false = false
  stream
    .once('MessageHeader', header => stream.emit('MessageHeader', header))
    .on('data', (chunk: Buffer) => ciphertext.push(chunk))

  // This will check both Uint8Array|Buffer
  if (plaintext instanceof Uint8Array) {
    stream.end(plaintext)
  } else if (typeof plaintext === 'string') {
    stream.end(Buffer.from(plaintext, encoding))
  } else if (plaintext.readable) {
    plaintext.pipe(stream)
  } else {
    throw new Error('Unsupported plaintext')
  }

  await finishedAsync(stream)
  if (!messageHeader) throw new Error('Unknown format')

  return {
    ciphertext: Buffer.concat(ciphertext),
    messageHeader
  }
}

function finishedAsync (stream: Duplexify) {
  return new Promise((resolve, reject) => {
    finished(stream, (err: Error) => err ? reject(err) : resolve())
  })
}
