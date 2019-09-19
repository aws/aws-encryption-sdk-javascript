import {
  KeyringNode, // eslint-disable-line no-unused-vars
  NodeMaterialsManager // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import {
  encryptStream,
  EncryptStreamInput // eslint-disable-line no-unused-vars
} from './encrypt_stream'

// @ts-ignore
import { finished } from 'readable-stream'
import { Readable, Duplex } from 'stream' // eslint-disable-line no-unused-vars
import { MessageHeader } from '@aws-crypto/serialize' // eslint-disable-line no-unused-vars

interface EncryptInput extends EncryptStreamInput {
  encoding?: BufferEncoding
}

export interface EncryptOutput {
  result: Buffer
  messageHeader: MessageHeader
}

export async function encrypt (
  cmm: KeyringNode|NodeMaterialsManager,
  plaintext: Buffer|Uint8Array|Readable|string|NodeJS.ReadableStream,
  op: EncryptInput = {}
): Promise<EncryptOutput> {
  const stream = encryptStream(cmm, op)
  const { encoding } = op

  const result: Buffer[] = []
  let messageHeader: MessageHeader|false = false
  stream
    .once('MessageHeader', header => { messageHeader = header })
    .on('data', (chunk: Buffer) => result.push(chunk))

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
    result: Buffer.concat(result),
    messageHeader
  }
}

function finishedAsync (stream: Duplex) {
  return new Promise((resolve, reject) => {
    finished(stream, (err: Error) => err ? reject(err) : resolve())
  })
}
