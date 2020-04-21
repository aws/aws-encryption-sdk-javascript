// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { _getEncryptTestVectorIterator } from '../src/index'
import { EncryptManifestList, KeyList } from '../src/types'

const manifiest: EncryptManifestList = {
  manifest: {
    type: 'awses-encrypt',
    version: 1,
  },
  keys: 'file://0002-keys.v1.json',
  plaintexts: {
    small: 10240,
  },
  tests: {
    '0c9c3222-b8f6-4b5f-97bc-c2a97f5255b1': {
      plaintext: 'small',
      algorithm: '0014',
      'frame-size': 0,
      'encryption-context': {},
      'master-keys': [
        {
          type: 'aws-kms',
          key: 'us-west-2-decryptable',
        },
      ],
    },
  },
}

const keyList: KeyList = {
  manifest: {
    type: 'keys',
    version: 3,
  },
  keys: {
    'us-west-2-decryptable': {
      type: 'aws-kms',
      'key-id': 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
      encrypt: true,
      decrypt: true,
    },
  },
}

describe('_getEncryptTestVectorIterator', () => {
  it('returns a iterator that has a test', () => {
    const testIterator = _getEncryptTestVectorIterator(manifiest, keyList)
    const test = testIterator.next()
    expect(test.done).to.equal(false)
    expect(test.value.name).to.equal('0c9c3222-b8f6-4b5f-97bc-c2a97f5255b1')
  })
})
