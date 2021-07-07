// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import {
  EncryptedDataKey,
  AlgorithmSuiteIdentifier,
} from '@aws-crypto/material-management'

const partitionName = 'c15b9079-6d0e-42b6-8784-5e804b025692'
const encryptionContextEmpty = {
  name: 'encryptionContextEmpty',
  encryptionContext: {},
  hash: new Uint8Array([
    207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7,
    214, 32, 228, 5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71,
    208, 209, 60, 93, 133, 242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99,
    185, 49, 189, 71, 65, 122, 129, 165, 56, 50, 122, 249, 39, 218, 62,
  ]),
}

const encryptionContextFull = {
  name: 'encryptionContextFull',
  encryptionContext: { this: 'is', a: 'non-empty', encryption: 'context' },
  hash: new Uint8Array([
    4, 250, 62, 217, 137, 103, 44, 245, 231, 15, 24, 164, 62, 35, 99, 8, 4, 29,
    75, 147, 51, 243, 111, 68, 2, 126, 189, 113, 20, 150, 243, 92, 188, 56, 128,
    79, 167, 9, 114, 93, 83, 189, 146, 168, 7, 189, 229, 174, 231, 68, 184, 217,
    66, 18, 60, 223, 54, 127, 13, 7, 230, 79, 129, 73,
  ]),
}

const encryptedDataKey1 = {
  name: 'encryptedDataKey1',
  edk: new EncryptedDataKey({
    providerId: 'this is a provider ID',
    providerInfo: 'this is some key info',
    encryptedDataKey: new Uint8Array([
      115, 117, 112, 101, 114, 32, 115, 101, 99, 114, 101, 116, 32, 107, 101,
      121, 44, 32, 110, 111, 119, 32, 119, 105, 116, 104, 32, 101, 110, 99, 114,
      121, 112, 116, 105, 111, 110, 33,
    ]),
  }),
  hash: new Uint8Array([
    77, 138, 5, 121, 139, 177, 158, 207, 197, 6, 86, 176, 225, 219, 17, 12, 235,
    246, 228, 224, 132, 42, 230, 70, 246, 37, 237, 230, 33, 29, 39, 194, 212,
    238, 126, 96, 150, 9, 3, 1, 92, 86, 80, 70, 2, 224, 146, 138, 202, 66, 93,
    30, 70, 149, 167, 23, 3, 188, 218, 146, 233, 75, 48, 137,
  ]),
}

const encryptedDataKey2 = {
  name: 'encryptedDataKey2',
  edk: new EncryptedDataKey({
    providerId: 'another provider ID!',
    providerInfo: 'this is some different key info',
    encryptedDataKey: new Uint8Array([
      98, 101, 116, 116, 101, 114, 32, 115, 117, 112, 101, 114, 32, 115, 101,
      99, 114, 101, 116, 32, 107, 101, 121, 44, 32, 110, 111, 119, 32, 119, 105,
      116, 104, 32, 101, 110, 99, 114, 121, 112, 116, 105, 111, 110, 33,
    ]),
  }),
  hash: new Uint8Array([
    193, 42, 195, 148, 243, 54, 161, 194, 35, 244, 192, 45, 15, 222, 20, 45, 36,
    116, 66, 187, 117, 154, 224, 104, 188, 16, 209, 47, 224, 236, 73, 51, 105,
    132, 145, 12, 220, 38, 127, 135, 115, 178, 189, 130, 252, 5, 29, 132, 33,
    124, 116, 155, 177, 152, 194, 255, 29, 26, 220, 153, 47, 96, 252, 239,
  ]),
}

export const encryptionContextVectors = [
  encryptionContextEmpty,
  encryptionContextFull,
]
export const encryptedDataKeyVectors = [encryptedDataKey1, encryptedDataKey2]

type VectorHack = { arguments: [string, any]; id: string }
export const encryptCacheKeyVectors: VectorHack[] = [
  {
    arguments: [
      partitionName,
      {
        suite: undefined,
        encryptionContext: encryptionContextEmpty.encryptionContext,
      },
    ],
    id: 'rkrFAso1YyPbOJbmwVMjrPw+wwLJT7xusn8tA8zMe9e3+OqbtfDueB7bvoKLU3fsmdUvZ6eMt7mBp1ThMMB25Q==',
  },
  {
    arguments: [
      partitionName,
      {
        suite: {
          id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        },
        encryptionContext: encryptionContextEmpty.encryptionContext,
      },
    ],
    id: '3icBIkLK4V3fVwbm3zSxUdUQV6ZvZYUOLl8buN36g6gDMqAkghcGryxX7QiVABkW1JhB6GRp5z+bzbiuciBcKQ==',
  },
  {
    arguments: [
      partitionName,
      {
        suite: undefined,
        encryptionContext: encryptionContextFull.encryptionContext,
      },
    ],
    id: 'IHiUHYOUVUEFTc3BcZPJDlsWct2Qy1A7JdfQl9sQoV/ILIbRpoz9q7RtGd/MlibaGl5ihE66cN8ygM8A5rtYbg==',
  },
  {
    arguments: [
      partitionName,
      {
        suite: {
          id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        },
        encryptionContext: encryptionContextFull.encryptionContext,
      },
    ],
    id: 'mRNK7qhTb/kJiiyGPgAevp0gwFRcET4KeeNYwZHhoEDvSUzQiDgl8Of+YRDaVzKxAqpNBgcAuFXde9JlaRRsmw==',
  },
]

export const decryptCacheKeyVectors: VectorHack[] = [
  {
    arguments: [
      partitionName,
      {
        suite: {
          id: AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256,
        },
        encryptedDataKeys: [encryptedDataKey1.edk],
        encryptionContext: encryptionContextEmpty.encryptionContext,
      },
    ],
    id: 'n0zVzk9QIVxhz6ET+aJIKKOJNxtpGtSe1yAbu7WU5l272Iw/jmhlER4psDHJs9Mr8KYiIvLGSXzggNDCc23+9w==',
  },
  {
    arguments: [
      partitionName,
      {
        suite: {
          id: AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        },
        encryptedDataKeys: [encryptedDataKey1.edk, encryptedDataKey2.edk],
        encryptionContext: encryptionContextFull.encryptionContext,
      },
    ],
    id: '+rtwUe38CGnczGmYu12iqGWHIyDyZ44EvYQ4S6ACmsgS8VaEpiw0RTGpDk6Z/7YYN/jVHOAcNKDyCNP8EmstFg==',
  },
]
