// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  _getDecryptTestVectorIterator
} from '../src/index'
import { DecryptManifestList, KeyList } from '../src/types' // eslint-disable-line no-unused-vars
import { PassThrough } from 'stream'

const keyList: KeyList = {
  'manifest': {
    'type': 'keys',
    'version': 3
  },
  'keys': {
    'us-west-2-decryptable': {
      'type': 'aws-kms',
      'key-id': 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt',
      'encrypt': true,
      'decrypt': true
    }
  }
}

const manifest:DecryptManifestList = {
  'manifest': {
    'type': 'awses-decrypt',
    'version': 1
  },
  'client': {
    'name': 'aws/aws-encryption-sdk-python',
    'version': '1.3.8'
  },
  'keys': 'file://keys.json',
  'tests': {
    'c17b05d0-915e-44cc-98a3-cc29b71aa42b': {
      'plaintext': 'file://plaintexts/small',
      'ciphertext': 'file://ciphertexts/460bd892-c137-4178-8201-4ab5ee5d3041',
      'master-keys': [
        {
          'type': 'aws-kms',
          'key': 'us-west-2-decryptable'
        }
      ]
    }
  }
}

const filesMap = new Map([
  [
    'file://manifest.json', {
      async stream () {
        const stream = new PassThrough()
        setImmediate(() => stream.end(Buffer.from(JSON.stringify(manifest))))
        return stream
      }
    } as any
  ],
  [
    'file://keys.json', {
      async stream () {
        const stream = new PassThrough()
        setImmediate(() => stream.end(Buffer.from(JSON.stringify(keyList))))
        return stream
      }
    } as any
  ],
  [
    'file://ciphertexts/460bd892-c137-4178-8201-4ab5ee5d3041', {
      async stream () {
        return {} as any
      }
    } as any
  ],
  [
    'file://plaintexts/small', {
      async stream () {
        return {} as any
      }
    } as any
  ]
])

describe('_getDecryptTestVectorIterator', () => {
  it('returns a iterator that has a test', async () => {
    const testIterator = await _getDecryptTestVectorIterator(filesMap)
    const test = testIterator.next()
    expect(test.done).to.equal(false)
    expect(test.value.name).to.equal('c17b05d0-915e-44cc-98a3-cc29b71aa42b')
  })
})
