// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { _encryptStream } from './encrypt_stream'
import { _encrypt } from './encrypt'
import { CommitmentPolicy, needs } from '@aws-crypto/material-management-node'

type CurryFirst<fn extends (...a: any[]) => any> = fn extends (
  _: any,
  ...tail: infer TAIL
) => any
  ? TAIL
  : []

export function buildEncrypt(
  commitmentPolicy: CommitmentPolicy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
): {
  encryptStream: (
    ...args: CurryFirst<typeof _encryptStream>
  ) => ReturnType<typeof _encryptStream>
  encrypt: (...args: CurryFirst<typeof _encrypt>) => ReturnType<typeof _encrypt>
} {
  /* Precondition: node buildEncrypt needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')
  return {
    encryptStream: _encryptStream.bind({}, commitmentPolicy),
    encrypt: _encrypt.bind({}, commitmentPolicy),
  }
}
