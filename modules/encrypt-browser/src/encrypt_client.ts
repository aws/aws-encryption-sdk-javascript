// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { _encrypt } from './encrypt'
import {
  CommitmentPolicy,
  needs,
} from '@aws-crypto/material-management-browser'

type CurryFirst<fn extends (...a: any[]) => any> = fn extends (
  _: any,
  ...tail: infer TAIL
) => any
  ? TAIL
  : []

export function buildEncrypt(
  commitmentPolicy: CommitmentPolicy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
): {
  encrypt: (...args: CurryFirst<typeof _encrypt>) => ReturnType<typeof _encrypt>
} {
  /* Precondition: browser buildEncrypt needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')
  return {
    encrypt: _encrypt.bind({}, commitmentPolicy),
  }
}
