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
import { promisify } from 'util'
const finishedAsync = promisify(finished)

interface EncryptInput extends EncryptStreamInput {
  encoding?: string
}

export async function encrypt (
  cmm: NodeCryptographicMaterialsManager,
  plaintext: Buffer|Uint8Array|Readable|string,
  op: EncryptInput = {}
) {
  const stream = encryptStream(cmm, op)
  const { encoding } = op

  const ciphertext: Buffer[] = []
  stream.on('data', (chunk: Buffer) => ciphertext.push(chunk))

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

  return Buffer.concat(ciphertext)
}
