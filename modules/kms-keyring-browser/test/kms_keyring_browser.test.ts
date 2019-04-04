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
import { KmsKeyringBrowser } from '../src/kms_keyring_browser'
import { KeyringWebCrypto } from '@aws-crypto/material-management-browser'

describe('KmsKeyringNode', () => {
  it('instance of KeyringWebCrypto', () => {
    const test = new KmsKeyringBrowser({ discovery: true })
    expect(test instanceof KeyringWebCrypto).to.equal(true)
  })
})
