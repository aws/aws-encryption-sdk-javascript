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
