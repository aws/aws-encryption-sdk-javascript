import {
  KeyringNode,
  NodeMaterialsManager,
} from '@aws-crypto/material-management-node'
import { encryptStream, EncryptStreamInput } from './encrypt_stream'

// @ts-ignore
import { finished } from 'readable-stream'
import { Readable, Duplex } from 'stream'
import { MessageHeader } from '@aws-crypto/serialize'

interface EncryptInput extends EncryptStreamInput {
  encoding?: BufferEncoding
}

export interface EncryptOutput {
  result: Buffer
  messageHeader: MessageHeader
}

export async function encrypt(
  cmm: KeyringNode | NodeMaterialsManager,
  plaintext: Buffer | Uint8Array | Readable | string | NodeJS.ReadableStream,
  op: EncryptInput = {}
): Promise<EncryptOutput> {
  const { encoding } = op
  if (plaintext instanceof Uint8Array) {
    op.plaintextLength = plaintext.byteLength
  } else if (typeof plaintext === 'string') {
    plaintext = Buffer.from(plaintext, encoding)
    op.plaintextLength = plaintext.byteLength
  }

  const stream = encryptStream(cmm, op)
  const result: Buffer[] = []
  let messageHeader: MessageHeader | false = false
  stream
    .once('MessageHeader', (header) => {
      messageHeader = header
    })
    .on('data', (chunk: Buffer) => result.push(chunk))

  // This will check both Uint8Array|Buffer
  if (plaintext instanceof Uint8Array) {
    stream.end(plaintext)
  } else if (plaintext.readable) {
    plaintext.pipe(stream)
  } else {
    throw new Error('Unsupported plaintext')
  }

  await finishedAsync(stream)
  if (!messageHeader) throw new Error('Unknown format')

  return {
    result: Buffer.concat(result),
    messageHeader,
  }
}

async function finishedAsync(stream: Duplex) {
  return new Promise((resolve, reject) => {
    finished(stream, (err: Error) => (err ? reject(err) : resolve()))
  })
}
