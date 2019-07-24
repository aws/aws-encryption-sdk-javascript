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
import {
  _getEncryptTestVectorIterator
} from '../src/index'
import { EncryptManifestList, KeyList } from '../src/types' // eslint-disable-line no-unused-vars

const manifiest: EncryptManifestList = {
  'manifest': {
    'type': 'awses-encrypt',
    'version': 1
  },
  'keys': 'file://0002-keys.v1.json',
  'plaintexts': {
    'small': 10240
  },
  'tests': {
    '0c9c3222-b8f6-4b5f-97bc-c2a97f5255b1': {
      'plaintext': 'small',
      'algorithm': '0014',
      'frame-size': 0,
      'encryption-context': {},
      'master-keys': [
        {
          'type': 'aws-kms',
          'key': 'us-west-2-decryptable'
        }
      ]
    }
  }
}

const keyList: KeyList = {
  'manifest': {
    'type': 'keys',
    'version': 3
  },
  'keys': { 'us-west-2-decryptable': {
    'type': 'aws-kms',
    'key-id': 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
    'encrypt': true,
    'decrypt': true
  }
  }
}

describe('_getEncryptTestVectorIterator', () => {
  it('returns a iterator that has a test', () => {
    const testIterator = _getEncryptTestVectorIterator(manifiest, keyList)
    const test = testIterator.next()
    expect(test.done).to.equal(false)
    expect(test.value.name).to.equal('0c9c3222-b8f6-4b5f-97bc-c2a97f5255b1')
  })
})
