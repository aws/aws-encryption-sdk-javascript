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
  NodeCryptographicMaterialsManager, // eslint-disable-line no-unused-vars
  KeyringNode // eslint-disable-line no-unused-vars
} from '@aws-crypto/material-management-node'
import { ParseHeaderStream } from './parse_header_stream'
import { VerifyStream } from './verify_stream'
import { getDecipherStream } from './decipher_stream'
import Duplexify from 'duplexify'
import { Duplex } from 'stream' // eslint-disable-line no-unused-vars

// @ts-ignore
import { pipeline } from 'readable-stream'

export interface DecryptStreamOptions {
  maxBodySize?: number
}

export function decryptStream (
  cmm: NodeCryptographicMaterialsManager|KeyringNode,
  { maxBodySize } : DecryptStreamOptions = {}
): Duplex {
  /* If the cmm is not a MaterialsManager, wrap in one.
   * I am expecting the NodeCryptographicMaterialsManager to
   * handle non-keyring parameters.
   */
  cmm = cmm instanceof NodeCryptographicMaterialsManager
    ? cmm
    : new NodeCryptographicMaterialsManager(cmm)

  const parseHeaderStream = new ParseHeaderStream(cmm, { maxBodySize })
  const verifyStream = new VerifyStream({ maxBodySize })
  const decipherStream = getDecipherStream()

  pipeline(parseHeaderStream, verifyStream, decipherStream)

  const stream = new Duplexify(parseHeaderStream, decipherStream)

  // Forward header events
  parseHeaderStream
    .once('MessageHeader', header => stream.emit('MessageHeader', header))

  return stream
}
