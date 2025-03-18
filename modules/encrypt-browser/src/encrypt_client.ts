// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { _encrypt } from './encrypt'
import {
  CommitmentPolicy,
  ClientOptions,
  needs,
} from '@aws-crypto/material-management-browser'

type CurryFirst<fn extends (...a: any[]) => any> = fn extends (
  _: any,
  ...tail: infer TAIL
) => any
  ? TAIL
  : []

export function buildEncrypt(
  options: CommitmentPolicy | Partial<ClientOptions> = {}
): {
  encrypt: (...args: CurryFirst<typeof _encrypt>) => ReturnType<typeof _encrypt>
} {
  const {
    commitmentPolicy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    maxEncryptedDataKeys = false,
  } = typeof options === 'string' ? { commitmentPolicy: options } : options

  /* Precondition: browser buildEncrypt needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')
  /* Precondition: browser buildEncrypt needs a valid maxEncryptedDataKeys. */
  needs(
    maxEncryptedDataKeys === false || maxEncryptedDataKeys >= 1,
    'Invalid maxEncryptedDataKeys value.'
  )

  const clientOptions: ClientOptions = {
    commitmentPolicy,
    maxEncryptedDataKeys,
  }
  return {
    encrypt: _encrypt.bind({}, clientOptions),
  }
}
