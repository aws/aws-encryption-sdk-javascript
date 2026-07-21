// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeDefaultCryptographicMaterialsManager,
  KeyringNode,
  NodeMaterialsManager,
} from '@aws-crypto/material-management-node'
import { ParseHeaderStream } from './parse_header_stream'
import { VerifyStream } from './verify_stream'
import { getDecipherStream } from './decipher_stream'
import { DecryptParameters, DecryptStreamOptions } from './types'
import Duplexify from 'duplexify'
import { Duplex } from 'stream'

// @ts-ignore
import { pipeline, PassThrough } from 'readable-stream'

export function _decryptStream(
  decryptParameters: DecryptParameters,
  cmm: KeyringNode | NodeMaterialsManager,
  { maxBodySize }: DecryptStreamOptions = {}
): Duplex {
  /* If the cmm is a Keyring, wrap it with NodeDefaultCMM. */
  cmm =
    cmm instanceof KeyringNode
      ? new NodeDefaultCryptographicMaterialsManager(cmm)
      : cmm

  const parseHeaderStream = new ParseHeaderStream(
    decryptParameters.signaturePolicy,
    decryptParameters.clientOptions,
    cmm
  )
  const verifyStream = new VerifyStream({ maxBodySize })
  const decipherStream = getDecipherStream()

  /* decipherStream must have exactly one consumer so that every decrypted
   * frame reaches the caller. outputStream is that single consumer and is
   * surfaced as the readable side of the Duplexify returned below.
   */
  const outputStream = new PassThrough()
  const stream = new Duplexify(parseHeaderStream, outputStream)

  /* pipeline will _either_ stream.destroy or the callback.
   * decipherStream uses destroy to dispose the material.
   */
  pipeline(
    parseHeaderStream,
    verifyStream,
    decipherStream,
    outputStream,
    (err: Error) => {
      if (err) stream.emit('error', err)
    }
  )

  // Forward header events
  parseHeaderStream.once('MessageHeader', (header) =>
    stream.emit('MessageHeader', header)
  )

  return stream
}
