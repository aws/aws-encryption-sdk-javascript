// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  NodeDefaultCryptographicMaterialsManager,
  KeyringNode,
  NodeMaterialsManager,
  CommitmentPolicy,
} from '@aws-crypto/material-management-node'
import { ParseHeaderStream } from './parse_header_stream'
import { VerifyStream } from './verify_stream'
import { getDecipherStream } from './decipher_stream'
import Duplexify from 'duplexify'
import { Duplex } from 'stream'

// @ts-ignore
import { pipeline, PassThrough } from 'readable-stream'

export interface DecryptStreamOptions {
  maxBodySize?: number
}

export function _decryptStream(
  commitmentPolicy: CommitmentPolicy,
  cmm: KeyringNode | NodeMaterialsManager,
  { maxBodySize }: DecryptStreamOptions = {}
): Duplex {
  /* If the cmm is a Keyring, wrap it with NodeDefaultCMM. */
  cmm =
    cmm instanceof KeyringNode
      ? new NodeDefaultCryptographicMaterialsManager(cmm)
      : cmm

  const parseHeaderStream = new ParseHeaderStream(commitmentPolicy, cmm)
  const verifyStream = new VerifyStream({ maxBodySize })
  const decipherStream = getDecipherStream()
  const stream = new Duplexify(parseHeaderStream, decipherStream)

  /* pipeline will _either_ stream.destroy or the callback.
   * decipherStream uses destroy to dispose the material.
   * So I tack a pass though stream onto the end.
   */
  pipeline(
    parseHeaderStream,
    verifyStream,
    decipherStream,
    new PassThrough(),
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
