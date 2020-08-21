// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { _decryptStream } from './decrypt_stream'
import { _decrypt } from './decrypt'
import { CommitmentPolicy, needs } from '@aws-crypto/material-management-node'

type CurryFirst<fn extends (...a: any[]) => any> = fn extends (
  _: any,
  ...tail: infer TAIL
) => any
  ? TAIL
  : never

export function buildDecrypt(
  commitmentPolicy: CommitmentPolicy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
): {
  decryptStream: (
    ...args: CurryFirst<typeof _decryptStream>
  ) => ReturnType<typeof _decryptStream>
  decrypt: (...args: CurryFirst<typeof _decrypt>) => ReturnType<typeof _decrypt>
} {
  /* Precondition: node buildDecrypt needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')
  return {
    decryptStream: _decryptStream.bind({}, commitmentPolicy),
    decrypt: _decrypt.bind({}, commitmentPolicy),
  }
}
