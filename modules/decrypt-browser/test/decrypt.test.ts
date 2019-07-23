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

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import { decrypt } from '../src/index'
import { AlgorithmSuiteIdentifier } from '@aws-crypto/material-management-browser'
import * as fixtures from './fixtures'

describe('decrypt', () => {
  it('buffer', async () => {
    const { clearMessage: test, messageHeader } = await decrypt(
      fixtures.decryptKeyring(),
      fixtures.ciphertextAlgAes256GcmIv12Tag16HkdfSha384EcdsaP384()
    )

    expect(messageHeader.suiteId).to.equal(AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
    expect(messageHeader.encryptionContext).to.deep.equal(fixtures.encryptionContext())
    expect(test).to.deep.equal(fixtures.plaintext())
  })

  it('Precondition: The sequence number is required to monotonically increase, starting from 1.', async () => {
    return decrypt(
      fixtures.decryptKeyring(),
      fixtures.frameSequenceOutOfOrder()
    ).then(() => {
      throw new Error('should not succeed')
    }, err => {
      expect(err).to.be.instanceOf(Error)
    })
  })
})
