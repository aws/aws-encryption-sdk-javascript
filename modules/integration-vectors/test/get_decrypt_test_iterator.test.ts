// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  _getDecryptTestVectorIterator,
  AesKeyInfo,
  Client,
  DecryptManifest,
  DecryptManifestList,
  KeyList,
  KmsKeyInfo,
  RsaKeyInfo,
} from '../src/index'
import { PassThrough } from 'stream'

const ciphertext_path = 'file://relative/path/to/ciphertext'
const plaintext_path = 'file://relative/path/to/plaintext'
const cipherStream = 'encrypted text'
const plainTextStream = 'unencrypted text'
const defaultOutput = { output: { plaintext: plaintext_path } }
const defaultError = {
  error: { 'error-description': 'Permission denied when decrypting data key' },
}
const defaultMasterKeys: (RsaKeyInfo | AesKeyInfo | KmsKeyInfo)[] = [
  {
    type: 'aws-kms',
    key: 'us-west-2-decryptable',
  },
]
const decryptManifest: DecryptManifest = {
  type: 'awses-decrypt',
  version: 1,
}
const client: Client = {
  name: 'aws/aws-encryption-sdk-python',
  version: '1.3.8',
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
    'us-west-2-encrypt-only': {
      type: 'aws-kms',
      'key-id': 'arn:aws:kms:us-west-2:658956600833:alias/Encrypt',
      encrypt: true,
      decrypt: false,
    },
    'arn:aws:kms-not:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7':
      {
        encrypt: false,
        decrypt: false,
        type: 'aws-kms',
        'key-id':
          'arn:aws:kms-not:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7',
      },
  },
}

const defaultManifest: DecryptManifestList = {
  manifest: decryptManifest,
  client: client,
  keys: 'file://keys.json',
  tests: {
    '2d1e0da9-74f8-4817-842d-c2b973abed7c': {
      description: 'Single raw rsa provider decryption',
      ciphertext: ciphertext_path,
      'master-keys': defaultMasterKeys,
      result: defaultOutput,
    },
    'f7f3416b-7527-4108-8d15-6d0d5a377a2c': {
      ciphertext: ciphertext_path,
      'master-keys': defaultMasterKeys,
      result: defaultOutput,
    },
  },
}

function mockReadManifest(
  manifest: DecryptManifestList,
  ciphertext: string,
  cipherStream: string,
  keyList: KeyList,
  manifest_result?: string, //Result object of manifest holding plaintext file path (possibly undefined)
  plainTextStream?: string //String content of plaintext (possibly undefined)
) {
  const mockFileMap = new Map([
    [
      'file://manifest.json',
      {
        //TODO find a better way to mock StreamEntry
        async stream() {
          const a_stream = new PassThrough()
          setImmediate(() =>
            a_stream.end(Buffer.from(JSON.stringify(manifest)))
          )
          return a_stream
        },
      } as any,
    ],
    [
      'file://keys.json',
      {
        async stream() {
          const a_stream = new PassThrough()
          setImmediate(() => a_stream.end(Buffer.from(JSON.stringify(keyList))))
          return a_stream
        },
      } as any,
    ],
    [
      ciphertext,
      {
        async stream() {
          const a_stream = new PassThrough()
          setImmediate(() =>
            a_stream.end(Buffer.from(JSON.stringify(cipherStream)))
          )
          return a_stream
        },
      } as any,
    ],
  ])

  if (manifest_result) {
    mockFileMap.set(manifest_result, {
      async stream() {
        const a_stream = new PassThrough()
        if (plainTextStream)
          setImmediate(() =>
            a_stream.end(Buffer.from(JSON.stringify(plainTextStream)))
          )
        return a_stream
      },
    } as any)
  }
  return mockFileMap
}

describe('_getDecryptTestVectorIterator yields Decrypt Tests', () => {
  it('returns a iterator that has positive tests', async () => {
    const testIterator = await _getDecryptTestVectorIterator(
      mockReadManifest(
        defaultManifest,
        ciphertext_path,
        cipherStream,
        keyList,
        plaintext_path,
        plainTextStream
      )
    )
    let test = testIterator.next()
    expect(test.done).to.equal(false)
    expect(test.value.name).to.equal('2d1e0da9-74f8-4817-842d-c2b973abed7c')
    expect(test.value.description).to.equal(
      'Single raw rsa provider decryption'
    )
    if ('error' in test.value) expect(test.value.error).to.be.undefined
    expect(test.value.plainTextStream).to.not.be.undefined

    test = testIterator.next()
    expect(test.value.name).to.equal('f7f3416b-7527-4108-8d15-6d0d5a377a2c')
    expect(test.value.description).to.be.undefined
  })

  it('returns a iterator that has negative tests', async () => {
    const manifestList: DecryptManifestList = {
      manifest: decryptManifest,
      client: client,
      keys: 'file://keys.json',
      tests: {
        'aeffc58b-2091-4a1a-a974-715ffb777b71': {
          description: 'Single aws kms provider decryption - no permissions',
          ciphertext: ciphertext_path,
          'master-keys': defaultMasterKeys,
          result: defaultError,
        },
      },
    }
    const testIterator = await _getDecryptTestVectorIterator(
      mockReadManifest(manifestList, ciphertext_path, cipherStream, keyList)
    )
    const test = testIterator.next()
    expect(test.done).to.equal(false)
    expect(test.value.name).to.equal('aeffc58b-2091-4a1a-a974-715ffb777b71')
    expect(test.value.description).to.equal(
      'Single aws kms provider decryption - no permissions'
    )
    expect(test.value.plainTextStream).to.be.undefined
    expect(test.value.errorDescription).to.not.undefined
  })
  it('Throws an error if manifest is missing', async () => {
    let throughAnError = false
    try {
      await _getDecryptTestVectorIterator(new Map())
    } catch (err) {
      expect(err).to.have.property(
        'message',
        'file://manifest.json does not exist'
      )
      throughAnError = true
    }
    expect(throughAnError).to.be.equal(
      true,
      '_getDecryptTestVectorIterator should have thrown an error'
    )
  })
  it('Throws an error if a plaintext is missing', async () => {
    const defaultManifest: DecryptManifestList = {
      manifest: decryptManifest,
      client: client,
      keys: 'file://keys.json',
      tests: {
        '2d1e0da9-74f8-4817-842d-c2b973abed7c': {
          description: 'Single raw rsa provider decryption',
          ciphertext: ciphertext_path,
          'master-keys': defaultMasterKeys,
          result: { output: { plaintext: '' } },
        },
      },
    }
    const mockManifest = mockReadManifest(
      defaultManifest,
      ciphertext_path,
      cipherStream,
      keyList,
      plaintext_path,
      plainTextStream
    )
    let throughAnError = false
    try {
      const testIterator = await _getDecryptTestVectorIterator(mockManifest)
      testIterator.next()
    } catch (err) {
      expect(err).to.have.property(
        'message',
        `no plaintext file for 2d1e0da9-74f8-4817-842d-c2b973abed7c: `
        // ": " above at the end are space for a variable that may not exist at this point
      )
      throughAnError = true
    }
    expect(throughAnError).to.be.equal(
      true,
      '_getDecryptTestVectorIterator should have thrown an error'
    )
  })
  it('Throws an error if the result is missing for a test', async () => {
    const defaultManifest = {
      manifest: decryptManifest,
      client: client,
      keys: 'file://keys.json',
      tests: {
        '2d1e0da9-74f8-4817-842d-c2b973abed7c': {
          description: 'Single raw rsa provider decryption',
          ciphertext: ciphertext_path,
          'master-keys': defaultMasterKeys,
          result: undefined,
        },
      },
    } as any
    const mockManifest = mockReadManifest(
      defaultManifest,
      ciphertext_path,
      cipherStream,
      keyList,
      plaintext_path,
      plainTextStream
    )
    let throughAnError = false
    try {
      const testIterator = await _getDecryptTestVectorIterator(mockManifest)
      testIterator.next()
    } catch (err) {
      expect(err).to.have.property(
        'message',
        `Could not parse vector for 2d1e0da9-74f8-4817-842d-c2b973abed7c`
      )
      throughAnError = true
    }
    expect(throughAnError).to.be.equal(
      true,
      '_getDecryptTestVectorIterator should have thrown an error'
    )
  })

  it('can read an mrk-aware vector', async () => {
    const testManifest: DecryptManifestList = {
      manifest: decryptManifest,
      client: client,
      keys: 'file://keys.json',
      tests: {
        'e6c7ad4c-5b24-44ce-a65e-62d402239b01': {
          ciphertext: ciphertext_path,
          'master-keys': [
            {
              type: 'aws-kms-mrk-aware',
              key: 'arn:aws:kms-not:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7',
            },
          ],
          result: {
            error: {
              'error-description':
                'Incorrect encrypted data key provider info: aws:kms:us-west-2:658956600833:key:mrk-80bd8ecdcd4342aebd84b7dc9da498a7',
            },
          },
        },
      },
    }
    const testIterator = await _getDecryptTestVectorIterator(
      mockReadManifest(
        testManifest,
        ciphertext_path,
        cipherStream,
        keyList,
        plaintext_path,
        plainTextStream
      )
    )

    const { value } = testIterator.next()
    expect(value.keysInfo[0][0].type, 'aws-kms-mrk-aware')
  })
})
