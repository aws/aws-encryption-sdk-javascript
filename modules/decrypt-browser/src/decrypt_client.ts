// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { _decrypt } from './decrypt'
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

export function buildDecrypt(
  commitmentPolicy: CommitmentPolicy
): {
  decrypt: (...args: CurryFirst<typeof _decrypt>) => ReturnType<typeof _decrypt>
} {
  /* Precondition: browser buildDecrypt needs a valid commitmentPolicy. */
  needs(CommitmentPolicy[commitmentPolicy], 'Invalid commitment policy.')
  return {
    decrypt: _decrypt.bind({}, commitmentPolicy),
  }
}
