// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This public interface for constructing info for the extract step of the KDF
 * is provided for the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other than the
 * Encryption SDK for JavaScript.
 *
 * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
 * The Key Derivation Algorithm section
 */

import {
  AlgorithmSuite,
  AlgorithmSuiteIdentifier,
  needs,
  NonCommittingAlgorithmSuiteIdentifier,
} from '@aws-crypto/material-management'
import { BinaryData } from './types'
import { concatBuffers } from './concat_buffers'
import { uInt16BE } from './uint_util'

export function kdfInfo(
  suiteId: AlgorithmSuiteIdentifier,
  messageId: BinaryData
) {
  /* Precondition: Info for non-committing suites *only*. */
  needs(
    NonCommittingAlgorithmSuiteIdentifier[suiteId],
    'Committing algorithm suite not supported.'
  )
  return concatBuffers(uInt16BE(suiteId), messageId)
}

/* Since these values are static
 * there is no need to import
 * a fromUtf8 function to convert them.
 *
 * [...Buffer.from('DERIVEKEY')]
 * 1. KeyLabel := DERIVEKEY as UTF-8 encoded bytes
 * [...Buffer.from('COMMITKEY')]
 * 2. CommitLabel := COMMITKEY as UTF-8 encoded bytes
 */
const KEY_LABEL = new Uint8Array([68, 69, 82, 73, 86, 69, 75, 69, 89])
const COMMIT_LABEL = new Uint8Array([67, 79, 77, 77, 73, 84, 75, 69, 89])

export function kdfCommitKeyInfo(suite: AlgorithmSuite) {
  /* Precondition: Info for committing algorithm suites only. */
  needs(
    suite.commitment === 'KEY',
    'Non committing algorithm suite not supported.'
  )
  return {
    keyLabel: concatBuffers(uInt16BE(suite.id), KEY_LABEL),
    commitLabel: COMMIT_LABEL.slice(),
  }
}
