// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { _decryptStream } from './decrypt_stream'
import { _decrypt } from './decrypt'
import {
  CommitmentPolicy,
  needs,
  SignaturePolicy,
  ClientOptions,
} from '@aws-crypto/material-management-node'

type CurryFirst<fn extends (...a: any[]) => any> = fn extends (
  _: any,
  ...tail: infer TAIL
) => any
  ? TAIL
  : never

export function buildDecrypt(
  options: CommitmentPolicy | Partial<ClientOptions> = {}
): {
  decryptUnsignedMessageStream: (
    ...args: CurryFirst<typeof _decryptStream>
  ) => ReturnType<typeof _decryptStream>
  decryptStream: (
    ...args: CurryFirst<typeof _decryptStream>
  ) => ReturnType<typeof _decryptStream>
  decrypt: (...args: CurryFirst<typeof _decrypt>) => ReturnType<typeof _decrypt>
} {
  const {
    commitmentPolicy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    maxEncryptedDataKeys = false,
  } = typeof options === 'string' ? { commitmentPolicy: options } : options

  /* Precondition: node buildDecrypt needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')
  /* Precondition: node buildDecrypt needs a valid maxEncryptedDataKeys. */
  needs(
    maxEncryptedDataKeys === false || maxEncryptedDataKeys >= 1,
    'Invalid maxEncryptedDataKeys value.'
  )

  const clientOptions: ClientOptions = {
    commitmentPolicy,
    maxEncryptedDataKeys,
  }
  return {
    decryptUnsignedMessageStream: _decryptStream.bind(
      {},
      {
        signaturePolicy: SignaturePolicy.ALLOW_ENCRYPT_FORBID_DECRYPT,
        clientOptions,
      }
    ),
    decryptStream: _decryptStream.bind(
      {},
      {
        signaturePolicy: SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
        clientOptions,
      }
    ),
    decrypt: _decrypt.bind(
      {},
      {
        signaturePolicy: SignaturePolicy.ALLOW_ENCRYPT_ALLOW_DECRYPT,
        clientOptions,
      }
    ),
  }
}

// @ts-ignore
const { decryptUnsignedMessageStream, decryptStream, decrypt } = buildDecrypt()
decryptUnsignedMessageStream({} as any)
