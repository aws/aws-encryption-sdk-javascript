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

import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management' // eslint-disable-line no-unused-vars
import { BinaryData } from './types' // eslint-disable-line no-unused-vars
import { concatBuffers } from './concat_buffers'
import { uInt16BE } from './uint_util'

export function kdfInfo (suiteId: AlgorithmSuiteIdentifier, messageId: BinaryData) {
  return concatBuffers(
    uInt16BE(suiteId),
    messageId
  )
}
