// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

export function basicMessageHeader() {
  // prettier-ignore
  return new Uint8Array([1,128,0,20,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99,0,2,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,8,102,105,114,115,116,75,101,121,0,5,1,2,3,4,5,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,9,115,101,99,111,110,100,75,101,121,0,5,6,7,8,9,0,2,0,0,0,0,12,0,0,16,0])
}

export function zeroByteEncryptionContextMessageHeader() {
  // see, 0,0 for context length, but _no_ element count
  // prettier-ignore
  return new Uint8Array([
    1,128,0,20,3,3,3,3,3,3,3,3,3,3,3,3,3,
    3,3,3,0,
    0, // see here, 0,0 for context length, but _no_ element count
    0,2,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,
    8,102,105,114,115,116,75,101,121,0,5,1,2,3,4,5,0,
    12,194,189,32,43,32,194,188,32,61,32,194,190,0,9,115,101,
    99,111,110,100,75,101,121,0,5,6,7,8,9,0,2,0,0,
    0,0,12,0,0,16,0,
  ])
}

export function suiteIdNotValidMessageHeader() {
  // prettier-ignore
  return new Uint8Array([1,128,0,0,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99,0,2,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,8,102,105,114,115,116,75,101,121,0,5,1,2,3,4,5,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,9,115,101,99,111,110,100,75,101,121,0,5,6,7,8,9,0,2,0,0,0,0,12,0,0,16,0]);
}

export function versionNotValidMessageHeader() {
  // prettier-ignore
  return new Uint8Array([256,128,0,20,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99,0,2,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,8,102,105,114,115,116,75,101,121,0,5,1,2,3,4,5,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,9,115,101,99,111,110,100,75,101,121,0,5,6,7,8,9,0,2,0,0,0,0,12,0,0,16,0]);
}

export function typeNotValidMessageHeader() {
  // prettier-ignore
  return new Uint8Array([1,256,0,20,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99,0,2,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,8,102,105,114,115,116,75,101,121,0,5,1,2,3,4,5,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,9,115,101,99,111,110,100,75,101,121,0,5,6,7,8,9,0,2,0,0,0,0,12,0,0,16,0]);
}

export function base64MessageHeader() {
  // prettier-ignore
  return new Uint8Array([65,89,65,65,70,65,77,68,65,119,77,68,65,119,77,68,65,119,77,68,65,119,77,68,65,119,77,65,75,119,65,67,65,65,116,112,98,109,90,118,99,109,49,104,100,71,108,118,98,103,65,77,119,114,48,103,75,121,68,67,118,67,65,57,73,77,75,43,65,65,82,122,98,50,49,108,65,65,90,119,100,87,74,115,97,87,77,65,65,103,65,77,119,114,48,103,75,121,68,67,118,67,65,57,73,77,75,43,65,65,104,109,97,88,74,122,100,69,116,108,101,81,65,70,65,81,73,68,66,65,85,65,68,77,75,57,73,67,115,103,119,114,119,103,80,83,68,67,118,103,65,74,99,50,86,106,98,50,53,107,83,50,86,53,65,65,85,71,66,119,103,74,65,65,73,65,65,65,65,65,68,65,65,65,69,65,65,61]);
}

export function reservedBytesNoZeroMessageHeader() {
  // prettier-ignore
  return new Uint8Array([1,128,0,20,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99,0,2,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,8,102,105,114,115,116,75,101,121,0,5,1,2,3,4,5,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,9,115,101,99,111,110,100,75,101,121,0,5,6,7,8,9,0,2,0,1,0,0,12,0,0,16,0]);
}

export function ivLengthMismatchMessageHeader() {
  // prettier-ignore
  return new Uint8Array([1,128,0,20,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99,0,2,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,8,102,105,114,115,116,75,101,121,0,5,1,2,3,4,5,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,9,115,101,99,111,110,100,75,101,121,0,5,6,7,8,9,0,2,0,0,0,0,8,0,0,16,0]);
}

export function basicFrameHeader() {
  // prettier-ignore
  return new Uint8Array([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

export function invalidSequenceNumberFrameHeader() {
  // prettier-ignore
  return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

export function finalFrameHeader() {
  // prettier-ignore
  return new Uint8Array([255,255,255,255,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,3,231]);
}

export function finalFrameHeaderZeroBytes() {
  // prettier-ignore
  return new Uint8Array([255,255,255,255,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0]);
}

export function invalidSequenceEndFinalFrameHeader() {
  // prettier-ignore
  return new Uint8Array([0,255,255,255,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,3,231]);
}

export function invalidSequenceNumberFinalFrameHeader() {
  // prettier-ignore
  return new Uint8Array([255,255,255,255,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,3,231]);
}

export function basicNonFrameHeader() {
  // prettier-ignore
  return new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0]);
}

export function invalidNonFrameHeaderContentLengthExcedsLimits() {
  // prettier-ignore
  return new Uint8Array([0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,15,255,255,255,224]);
}

export function basicEncryptionContext() {
  // prettier-ignore
  return new Uint8Array([0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99]);
}

export function missingDataEncryptionContext() {
  // prettier-ignore
  return new Uint8Array([0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108]);
}

export function tooMuchDataEncryptionContext() {
  // prettier-ignore
  return new Uint8Array([0,43,0,2,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99,0]);
}

export function duplicateKeysEncryptionContext() {
  // prettier-ignore
  return new Uint8Array([0,43,0,4,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,11,105,110,102,111,114,109,97,116,105,111,110,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,4,115,111,109,101,0,6,112,117,98,108,105,99,0,4,115,111,109,101,0,6,112,117,98,108,105,99]);
}

export function hasOwnPropertyEncryptionContext() {
  // prettier-ignore
  return new Uint8Array([0,34,0,1,0,14,104,97,115,79,119,110,80,114,111,112,101,114,116,121,0,14,97,114,98,105,116,114,97,114,121,86,97,108,117,101]);
}

export function basicFrameIV() {
  // prettier-ignore
  return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

export function basicNonFrameIV() {
  // prettier-ignore
  return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

export function headerAuthIV() {
  // prettier-ignore
  return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}

export function encryptedDataKey() {
  // prettier-ignore
  return new Uint8Array([0,2,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,8,102,105,114,115,116,75,101,121,0,5,1,2,3,4,5,0,12,194,189,32,43,32,194,188,32,61,32,194,190,0,9,115,101,99,111,110,100,75,101,121,0,5,6,7,8,9,0]);
}

export function ecdsaP256Signature() {
  // prettier-ignore
  return new Uint8Array([48,68,2,32,22,77,187,192,175,104,2,240,55,2,6,138,103,148,214,240,244,65,224,254,60,52,218,22,250,245,216,228,151,151,220,234,2,32,125,9,97,8,132,123,79,193,216,207,214,0,73,183,149,173,26,173,251,132,140,139,44,122,11,50,163,105,138,221,223,29]);
}

export function ecdsaP256SignatureInfo() {
  // prettier-ignore
  return new Uint8Array([0,70,48,68,2,32,22,77,187,192,175,104,2,240,55,2,6,138,103,148,214,240,244,65,224,254,60,52,218,22,250,245,216,228,151,151,220,234,2,32,125,9,97,8,132,123,79,193,216,207,214,0,73,183,149,173,26,173,251,132,140,139,44,122,11,50,163,105,138,221,223,29]);
}

export function basicV2MessageHeader() {
  // prettier-ignore
  return new Uint8Array([2,4,120,77,251,209,49,77,157,85,146,91,129,114,50,197,227,109,110,62,94,35,15,1,137,48,226,194,193,242,67,246,125,193,121,0,0,0,1,0,12,80,114,111,118,105,100,101,114,78,97,109,101,0,25,75,101,121,73,100,0,0,0,128,0,0,0,12,248,230,199,55,112,59,201,103,176,248,63,123,0,48,161,59,119,252,60,206,36,45,216,45,42,30,204,181,66,237,132,218,175,118,120,129,132,254,66,231,23,246,52,211,113,202,189,60,113,239,27,246,102,255,55,98,227,157,192,115,11,229,2,0,0,16,0,23,207,8,247,51,219,81,4,159,58,92,203,94,255,174,33,141,190,155,241,58,143,99,204,177,184,30,29,81,255,47,76,11,169,9,88,251,144,139,211,61,241,156,211,140,33,150,158])
}

export function threeEdksMessagePartialHeaderV1() {
  // prettier-ignore
  return new Uint8Array([
    1,  // version
    128,  // type
    0, 20,  // alg ID
    // message ID
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    0, 0,  // AAD length
    0, 3,  // EDK count
  ])
}

export function threeEdksMessagePartialHeaderV2() {
  // prettier-ignore
  return new Uint8Array([
    2,  // version
    4, 120,  // alg ID
    // message ID
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255,
    0, 0,  // AAD length
    0, 3,  // EDK count
  ])
}

export interface VectorTest {
  ciphertext: string
  commitment: string
  'content-encryption-key'?: string
  'message-id': string
  'encryption-context': { [s: string]: string }
  header: string
  status: boolean
  'decrypted-dek': string
  'keyring-type': 'static' | 'aws-kms'
  'plaintext-frames'?: string[]
  exception: null | string
  comment: string
  frames?: string[]
  footer?: string
}
export function compatibilityVectors(): {
  tests: VectorTest[]
  title: string
  date: string
  status: string
} {
  return {
    title: 'AWS Encryption SDK - Message Format V2 Test Vectors',
    date: '2020-09-18',
    status: '2.0 Release',
    tests: [
      {
        ciphertext:
          'AgR4TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXkAAAABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAz45sc3cDvJZ7D4P3sAMKE7d/w8ziQt2C0qHsy1Qu2E2q92eIGE/kLnF/Y003HKvTxx7xv2Zv83YuOdwHML5QIAABAAF88I9zPbUQSfOlzLXv+uIY2+m/E6j2PMsbgeHVH/L0wLqQlY+5CL0z3xnNOMIZae/////wAAAAEAAAAAAAAAAAAAAAEAAAAOSZBKHHRpTwXOFTQVGapXXj5CwXBMouBB2ucaIJVm',
        commitment: 'F88I9zPbUQSfOlzLXv+uIY2+m/E6j2PMsbgeHVH/L0w=',
        'content-encryption-key':
          'V67301yMJtk0jxOc3QJeBac6uKxO3XylWtkKTYmUU+M=',
        'decrypted-dek': '+p6+whPVw9kOrYLZFMRBJ2n6Vli6T/7TkjDouS+25s0=',
        exception: null,
        frames: [
          '/////wAAAAEAAAAAAAAAAAAAAAEAAAAOSZBKHHRpTwXOFTQVGapXXj5CwXBMouBB2ucaIJVm',
        ],
        header:
          'AgR4TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXkAAAABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAz45sc3cDvJZ7D4P3sAMKE7d/w8ziQt2C0qHsy1Qu2E2q92eIGE/kLnF/Y003HKvTxx7xv2Zv83YuOdwHML5QIAABAAF88I9zPbUQSfOlzLXv+uIY2+m/E6j2PMsbgeHVH/L0wLqQlY+5CL0z3xnNOMIZae',
        'encryption-context': {},
        'keyring-type': 'static',
        'message-id': 'TfvRMU2dVZJbgXIyxeNtbj5eIw8BiTDiwsHyQ/Z9wXk=',
        'plaintext-frames': ['GoodCommitment'],
        status: true,
        comment: '1. Non-KMS key provider',
      },
      {
        ciphertext:
          'AgR4b1/73X5ErILpj0aSQIx6wNnHLEcNLxPzA0m6vYRr7kAAAAABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAypJmXwyizUr3/pyvIAMHLU/i5GhZlGayeYC5w/CjUobyGwN4QpeMB0XpNDGTM0f1Zx72V4uM2H5wMjy/hm2wIAABAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh/pQM2VSvliz2Qgi5JZf2ta/////wAAAAEAAAAAAAAAAAAAAAEAAAANS4Id4+dVHhPrvuJHEiOswo6YGSRjSGX3VDrt+0s=',
        commitment: 'G7WvkcK+MF0AWhp8XhNcd8k5defmfi1dMqSgsN9v8e4=',
        'content-encryption-key':
          'Q/TITiE1CtPUr736a90u/WjxXmKd/M8bfb7Mo4TAXwA=',
        'decrypted-dek': '8Bu+AFAu9ZT8BwYK+QAKXKQ2iaySSiQwlPUrKMf6fdo=',
        exception: 'EXCEPTION: Invalid commitment',
        frames: [
          '/////wAAAAEAAAAAAAAAAAAAAAEAAAANS4Id4+dVHhPrvuJHEiOswo6YGSRjSGX3VDrt+0s=',
        ],
        'encryption-context': {},
        header:
          'AgR4b1/73X5ErILpj0aSQIx6wNnHLEcNLxPzA0m6vYRr7kAAAAABAAxQcm92aWRlck5hbWUAGUtleUlkAAAAgAAAAAypJmXwyizUr3/pyvIAMHLU/i5GhZlGayeYC5w/CjUobyGwN4QpeMB0XpNDGTM0f1Zx72V4uM2H5wMjy/hm2wIAABAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh/pQM2VSvliz2Qgi5JZf2ta',
        'keyring-type': 'static',
        'message-id': 'b1/73X5ErILpj0aSQIx6wNnHLEcNLxPzA0m6vYRr7kA=',
        status: false,
        comment: '2. Non-KMS key provider (Expected Failure)',
      },
      {
        ciphertext:
          'AgV4vjf7DnZHP0MgQ4/QHZH1Z/1Lt24oyMR0DigenSpro9wAjgAEAAUwVGhpcwACaXMAAzFhbgAKZW5jcnlwdGlvbgAIMmNvbnRleHQAB2V4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQXRnM3JwOEVBNFFhNnBmaTk3MUlTNTk3NHpOMnlZWE5vSmtwRHFPc0dIYkVaVDRqME5OMlFkRStmbTFVY01WdThnPT0AAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMOTLXUpQGBjgD+EYIAgEQgDsqRrwjQTGW0pA78dc+2Y/IqUrG7eAO4hZ07BNJEnd1d3+gUqW6Yunk8qyN9ryxdY8s4PshzJ7lyXIDuwIAABAABc0DWynVSZ1Fh1cLh1Aq/mNPeyzD3yqpiKEBBUosdod2yzOfJTZ0H1mhwgJPJZSr/////wAAAAEAAAAAAAAAAAAAAAEAAAAJ+m45xgKSc5k+9oOlZEBdaNvusGVs1XyesABnMGUCMCoWR62YhnklwXEuj63nCz8qK8O4UOuR71bP3RiWfZHYQtkrrzV7ukj2Nseghpyt4gIxAKquEtCPigr+heUFSAMRDJ7YEbLgisSgUqkHQhfqOwG2YFNKySG/CR0SNlfisJNovQ==',
        commitment: 'Bc0DWynVSZ1Fh1cLh1Aq/mNPeyzD3yqpiKEBBUosdoc=',
        'content-encryption-key':
          'YqelE6F+cSyDvu7BTR8ZnPQzZ+7NumfwuwdOzaRb44g=',
        'decrypted-dek': 'FX5R4LJUJ1XkzcV5GGRS9MSdtc+2kzyvEsVFiETwdi4=',
        exception: null,
        footer:
          'AGcwZQIwKhZHrZiGeSXBcS6PrecLPyorw7hQ65HvVs/dGJZ9kdhC2SuvNXu6SPY2x6CGnK3iAjEAqq4S0I+KCv6F5QVIAxEMntgRsuCKxKBSqQdCF+o7AbZgU0rJIb8JHRI2V+Kwk2i9',
        frames: [
          '/////wAAAAEAAAAAAAAAAAAAAAEAAAAJ+m45xgKSc5k+9oOlZEBdaNvusGVs1XyesA==',
        ],
        header:
          'AgV4vjf7DnZHP0MgQ4/QHZH1Z/1Lt24oyMR0DigenSpro9wAjgAEAAUwVGhpcwACaXMAAzFhbgAKZW5jcnlwdGlvbgAIMmNvbnRleHQAB2V4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQXRnM3JwOEVBNFFhNnBmaTk3MUlTNTk3NHpOMnlZWE5vSmtwRHFPc0dIYkVaVDRqME5OMlFkRStmbTFVY01WdThnPT0AAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMOTLXUpQGBjgD+EYIAgEQgDsqRrwjQTGW0pA78dc+2Y/IqUrG7eAO4hZ07BNJEnd1d3+gUqW6Yunk8qyN9ryxdY8s4PshzJ7lyXIDuwIAABAABc0DWynVSZ1Fh1cLh1Aq/mNPeyzD3yqpiKEBBUosdod2yzOfJTZ0H1mhwgJPJZSr',
        'encryption-context': {
          '0This': 'is',
          '1an': 'encryption',
          '2context': 'example',
          'aws-crypto-public-key':
            'Atg3rp8EA4Qa6pfi971IS5974zN2yYXNoJkpDqOsGHbEZT4j0NN2QdE+fm1UcMVu8g==',
        },
        'keyring-type': 'aws-kms',
        'message-id': 'vjf7DnZHP0MgQ4/QHZH1Z/1Lt24oyMR0DigenSpro9w=',
        'plaintext-frames': ['Plaintext'],
        status: true,
        comment: '3. KMS key provider (with ECDSA)',
      },
      {
        ciphertext:
          'AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAw9EJqts2PkPA43eeMCARCAO9JPXvk6hofpX8P50mlDfAEwIiJc9sTS82KeLPBiZRnvmWcf2YSceNCoKTOB819M1auXncAYO8JJ/VzPAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAw4v1P6lkHuuyIOZ7ECARCAO0iAkJa/Ivo37+t5rryGAGMiIHuamdq21HBOULwcGmMzCT69PWNgm1l59xq+8AOinEEzohfm2jBueXA2AgAAEABDPYN/Wct+m8YzTRVK/4MRCcY3LZj4tayFiL/376umUUTUenheMypVEflUomVblvr/////AAAAAQAAAAAAAAAAAAAAAQAAAAlCp+rAMHiuKyGr0KRmjDC6C7TXAvAwtFjR',
        commitment: 'Qz2Df1nLfpvGM00VSv+DEQnGNy2Y+LWshYi/9++rplE=',
        'content-encryption-key':
          'qSmd3ox7r+cIeGmJhuguY3i5S/LMKVUYJGgWR7rhE6M=',
        'decrypted-dek': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'encryption-context': {},
        exception: null,
        frames: [
          '/////wAAAAEAAAAAAAAAAAAAAAEAAAAJQqfqwDB4rishq9CkZowwugu01wLwMLRY0Q==',
        ],
        header:
          'AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAw9EJqts2PkPA43eeMCARCAO9JPXvk6hofpX8P50mlDfAEwIiJc9sTS82KeLPBiZRnvmWcf2YSceNCoKTOB819M1auXncAYO8JJ/VzPAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAw4v1P6lkHuuyIOZ7ECARCAO0iAkJa/Ivo37+t5rryGAGMiIHuamdq21HBOULwcGmMzCT69PWNgm1l59xq+8AOinEEzohfm2jBueXA2AgAAEABDPYN/Wct+m8YzTRVK/4MRCcY3LZj4tayFiL/376umUUTUenheMypVEflUomVblvo=',
        'message-id': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '4. Key = zero, Message ID = zero',
      },
      {
        ciphertext:
          'AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDOl5m0bj8TSUWO4GBwIBEIA7V0a+DvNMcbD7jfMcMuk0Rz8vB3oEp9wlIATpXzJmjqWefsFPJy5izbrFcR5CydFN2KS3h7E/9AjlQiUAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDIbOPUE8vBwp3Z6CLQIBEIA7mvK9rkzLwhrM+A8KXqqfj6pktEbnUrfggiAYnpss2KuZhM/vh/ha1SE9mSXwd4SFGVYOG5Q9/WevH1ICAAAQAEM9g39Zy36bxjNNFUr/gxEJxjctmPi1rIWIv/fvq6ZRrGZZkIZ1T4L6ZU5vqj/DrP////8AAAABAAAAAAAAAAAAAAABAAAACYppWXO1LeMi/qxGk3haWIs2N4VSEWHPa7cAZzBlAjAnb0SKcZVySyKIYvYvJA0yDUuftkXNoi01Umw+9MpwGh/y3cR3+TKU4DnNuljEkfACMQCNMCiS30oMIWNlhrWBQ852fhfhLvg8jLGIYLwFhEE9NrnyDYfj2H8Ej7+qK4C9OTY=',
        commitment: 'Qz2Df1nLfpvGM00VSv+DEQnGNy2Y+LWshYi/9++rplE=',
        'content-encryption-key':
          'FMygob85VLR2Y0EWK6hq5K4OQI2fYoVt0qQp9VWrRAE=',
        'decrypted-dek': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'encryption-context': {
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: null,
        footer:
          'AGcwZQIwJ29EinGVcksiiGL2LyQNMg1Ln7ZFzaItNVJsPvTKcBof8t3Ed/kylOA5zbpYxJHwAjEAjTAokt9KDCFjZYa1gUPOdn4X4S74PIyxiGC8BYRBPTa58g2H49h/BI+/qiuAvTk2',
        frames: [
          '/////wAAAAEAAAAAAAAAAAAAAAEAAAAJimlZc7Ut4yL+rEaTeFpYizY3hVIRYc9rtw==',
        ],
        header:
          'AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDOl5m0bj8TSUWO4GBwIBEIA7V0a+DvNMcbD7jfMcMuk0Rz8vB3oEp9wlIATpXzJmjqWefsFPJy5izbrFcR5CydFN2KS3h7E/9AjlQiUAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDIbOPUE8vBwp3Z6CLQIBEIA7mvK9rkzLwhrM+A8KXqqfj6pktEbnUrfggiAYnpss2KuZhM/vh/ha1SE9mSXwd4SFGVYOG5Q9/WevH1ICAAAQAEM9g39Zy36bxjNNFUr/gxEJxjctmPi1rIWIv/fvq6ZRrGZZkIZ1T4L6ZU5vqj/DrA==',
        'message-id': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '5. Key = zero, Message ID = zero (signed)',
      },
      {
        ciphertext:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyLV34wpxvMYsbEiU8CARCAO0bxzvbstOlsWM526OaxxrXGZcngJ/76lY0BzOXIX9AXwtTsJo665uBaTIr4/vRykIKYzaZHSAuXKsdgAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzI7Ml/HzSTtW5N/8wCARCAO8cdJ+NTV5FmL2ct3yQSJDgoyBdZPBdm4jU9l4jcDt5lbYFd1zDxgPeNk31VXLPNsX0mTx0OaEPIK6KlAgAAEAACl+KPtzMY6hHYeXFawsClEaCgrwZP3NxMctmWVgd4gnqay0u/SsaSuLWWsLJs7bH/////AAAAAf//////////AAAAAQAAAAlL5waUrU/1SiTVGftdt6I+oiP381iEHj9x',
        commitment: 'Apfij7czGOoR2HlxWsLApRGgoK8GT9zcTHLZllYHeII=',
        'content-encryption-key':
          '4zt1+EPrf/1X9lyHGwI9TaX4KF6nMIZLK6BTRzsHkUc=',
        'decrypted-dek': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'encryption-context': {},
        exception: null,
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJS+cGlK1P9Uok1Rn7XbeiPqIj9/NYhB4/cQ==',
        ],
        header:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyLV34wpxvMYsbEiU8CARCAO0bxzvbstOlsWM526OaxxrXGZcngJ/76lY0BzOXIX9AXwtTsJo665uBaTIr4/vRykIKYzaZHSAuXKsdgAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzI7Ml/HzSTtW5N/8wCARCAO8cdJ+NTV5FmL2ct3yQSJDgoyBdZPBdm4jU9l4jcDt5lbYFd1zDxgPeNk31VXLPNsX0mTx0OaEPIK6KlAgAAEAACl+KPtzMY6hHYeXFawsClEaCgrwZP3NxMctmWVgd4gnqay0u/SsaSuLWWsLJs7bE=',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '6. Key = zero, Message ID = example',
      },
      {
        ciphertext:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDLIcLILCEW0b/akcFQIBEIA7sN7bHvnMwOLqzk8ZQgRTZSyIRSbXV8XucXF6jh/cB6q7KQHak72WGEowX06j+q1CmqIHQsHgLJJ7Y7cAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDEJci+3Rbh2YQr2wVgIBEIA78+/l+kW07ZozOJ/aA2eZ3KlNAy6rT6DC/18vT+rT8kXgJAtvcLfYGL8QvVcZnxeLX4ebtzdzIWmUZhACAAAQAAKX4o+3MxjqEdh5cVrCwKURoKCvBk/c3Exy2ZZWB3iCOgF1daFLUF+WmSaKQstsl/////8AAAAB//////////8AAAABAAAACQY49UBR9fGrbSLGqwWF/gAL17cwTR18A5MAZjBkAjAKrkLQ1xAPssfM1rfJibkZQb0260Mm2vRCetEgl3RDJx/sBSxnRBZo53aRQHML6rwCMHmqQaG/tBzeWp9N0xengvRNL7eHJFSLxbCCgOOHlUllPWa03oYrvRCUPQ9RfREeDg==',
        commitment: 'Apfij7czGOoR2HlxWsLApRGgoK8GT9zcTHLZllYHeII=',
        'content-encryption-key':
          'JsOW8DkFqoSmowhVoHjl5YhgMFWqtt8qluHB5vMtH7Y=',
        'decrypted-dek': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'encryption-context': {
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: null,
        footer:
          'AGYwZAIwCq5C0NcQD7LHzNa3yYm5GUG9NutDJtr0QnrRIJd0Qycf7AUsZ0QWaOd2kUBzC+q8AjB5qkGhv7Qc3lqfTdMXp4L0TS+3hyRUi8WwgoDjh5VJZT1mtN6GK70QlD0PUX0RHg4=',
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJBjj1QFH18attIsarBYX+AAvXtzBNHXwDkw==',
        ],
        header:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDLIcLILCEW0b/akcFQIBEIA7sN7bHvnMwOLqzk8ZQgRTZSyIRSbXV8XucXF6jh/cB6q7KQHak72WGEowX06j+q1CmqIHQsHgLJJ7Y7cAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDEJci+3Rbh2YQr2wVgIBEIA78+/l+kW07ZozOJ/aA2eZ3KlNAy6rT6DC/18vT+rT8kXgJAtvcLfYGL8QvVcZnxeLX4ebtzdzIWmUZhACAAAQAAKX4o+3MxjqEdh5cVrCwKURoKCvBk/c3Exy2ZZWB3iCOgF1daFLUF+WmSaKQstslw==',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '7. Key = zero, Message ID = example (signed)',
      },
      {
        ciphertext:
          'AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzyYxT13KXwmUdiy88CARCAOzGOUQoGACVGrO4G0peHG71kP2zcDJpbdgZwUJBED49U3gpnQpBTWp2hp1N7Qti/fxNTccVKGZzutdZoAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwP+Chc1R00x7BpDcsCARCAO3vvz3yc9wbc2BBLvX0Mdc4Z5gVDOCLOXuNiSNmCFqHAZqVgwQZPJb8xg+LQ0Li+luAffrro75j4bV3ZAgAAEABCgKFhvD9vTCe32kD42QLPj7aksASoP1T02N4az5lpkszyG+f3sYswBonWP9RwXEv/////AAAAAf//////////AAAAAQAAAAl9Q+pOIP6ElqvCiPy7rOA36dQnyyOGg463',
        commitment: 'QoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZI=',
        'content-encryption-key':
          'GQvu4IjcA/2Yfpk1GYkuT/7ZBOlzHYuwVvvrEfVOfXw=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {},
        exception: null,
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJfUPqTiD+hJarwoj8u6zgN+nUJ8sjhoOOtw==',
        ],
        header:
          'AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzyYxT13KXwmUdiy88CARCAOzGOUQoGACVGrO4G0peHG71kP2zcDJpbdgZwUJBED49U3gpnQpBTWp2hp1N7Qti/fxNTccVKGZzutdZoAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwP+Chc1R00x7BpDcsCARCAO3vvz3yc9wbc2BBLvX0Mdc4Z5gVDOCLOXuNiSNmCFqHAZqVgwQZPJb8xg+LQ0Li+luAffrro75j4bV3ZAgAAEABCgKFhvD9vTCe32kD42QLPj7aksASoP1T02N4az5lpkszyG+f3sYswBonWP9RwXEs=',
        'message-id': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '8. Key = example, Message ID = zero',
      },
      {
        ciphertext:
          'AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDHeEI3Z1nYS1NsWO3gIBEIA7kheJ0Nc6B3mnlQSehdOnpAQfk1DWf4Yio61pzLJJxdjAL/mxnkczLPTUbbbQKPwyAozKoE324+Tbu0wAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDGY7wZesL6TorCErTwIBEIA7/+0ch6ZtFmPqI8UkrwueqwRBJsFGNWcFqgL9jnyVGkw9Nb422X9wzAvmAZxffxbdmTNEzTaQPiOTpOMCAAAQAEKAoWG8P29MJ7faQPjZAs+PtqSwBKg/VPTY3hrPmWmSO8OkA7vPXdTYugnXxz8umP////8AAAAB//////////8AAAABAAAACcv5HJwalZMTSUDIh9Z5MNr+qA7gnMqHxM0AZzBlAjEAin8CuSVzytkAqI+TiqPyaslB8bb1OFd2RY1xUuIeFCmYZSo+53ok5nyTquzxEGRLAjALrF/ggOtvZ8qUNJCWaYOz9UGYll3YmU8de0x6NEwCj5XednEd8Jesw9mOZ5+qbSg=',
        commitment: 'QoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZI=',
        'content-encryption-key':
          '61/Wu0/yvuQ2KHTjUpHpSIPSouZb/AtU8jl2HtEmjIs=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: null,
        footer:
          'AGcwZQIxAIp/Arklc8rZAKiPk4qj8mrJQfG29ThXdkWNcVLiHhQpmGUqPud6JOZ8k6rs8RBkSwIwC6xf4IDrb2fKlDSQlmmDs/VBmJZd2JlPHXtMejRMAo+V3nZxHfCXrMPZjmefqm0o',
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJy/kcnBqVkxNJQMiH1nkw2v6oDuCcyofEzQ==',
        ],
        header:
          'AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDHeEI3Z1nYS1NsWO3gIBEIA7kheJ0Nc6B3mnlQSehdOnpAQfk1DWf4Yio61pzLJJxdjAL/mxnkczLPTUbbbQKPwyAozKoE324+Tbu0wAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDGY7wZesL6TorCErTwIBEIA7/+0ch6ZtFmPqI8UkrwueqwRBJsFGNWcFqgL9jnyVGkw9Nb422X9wzAvmAZxffxbdmTNEzTaQPiOTpOMCAAAQAEKAoWG8P29MJ7faQPjZAs+PtqSwBKg/VPTY3hrPmWmSO8OkA7vPXdTYugnXxz8umA==',
        'message-id': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '9. Key = example, Message ID = zero (signed)',
      },
      {
        ciphertext:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAx3EP1N/LumYE8aNewCARCAO8m7yeBMjLVEHoeMmbylI3QdPRoqp+mJDgcN5ykeh5OpAr7flh9VlZcik9OOPViXcGSKodlDLibhi1W1AAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAztBB+UBueMi1l2QyQCARCAOw8NELkDmYdYArDjxBiHF3nlbbMjhPN/6tsCTrryk78nIe1kUj6dhOW4jv9UAK9v8II+kLeOwq1JsCr0AgAAEADxsVyYp96/hpK+FPm+py4GHisVMco6nM7oDHr08PByitCSr8UpuX4JwQvWDz3Em/b/////AAAAAf//////////AAAAAQAAAAnIeIJlIPwbFrcG232KWGshMJ9+1gKublnM',
        commitment: '8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcoo=',
        'content-encryption-key':
          'o+avOr85YWbGFlh4G5kA5I8wBW4qre0d5/+BsW/uOis=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {},
        exception: null,
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJyHiCZSD8Gxa3Btt9ilhrITCfftYCrm5ZzA==',
        ],
        header:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAx3EP1N/LumYE8aNewCARCAO8m7yeBMjLVEHoeMmbylI3QdPRoqp+mJDgcN5ykeh5OpAr7flh9VlZcik9OOPViXcGSKodlDLibhi1W1AAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAztBB+UBueMi1l2QyQCARCAOw8NELkDmYdYArDjxBiHF3nlbbMjhPN/6tsCTrryk78nIe1kUj6dhOW4jv9UAK9v8II+kLeOwq1JsCr0AgAAEADxsVyYp96/hpK+FPm+py4GHisVMco6nM7oDHr08PByitCSr8UpuX4JwQvWDz3Em/Y=',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '10. Key = example, Message ID = example',
      },
      {
        ciphertext:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFJv9+79usIu0JHDLwIBEIA7SELzODxUMVbIbIzq4Bxlq5VgO5IByEOFWGi+Q+NxyubE2cwXwVLptW6y/jiLn6CGrDaBzxuthwHgxmEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFGVND+QpXSW67k+5gIBEIA7Lm792H0cZeQGH0D1MXjYnkOdjSMRSCSjU9nmMwEuOdr16kYAXBul9dY4KpWyRNTfrWJxfoEZh4uldlcCAAAQAPGxXJin3r+Gkr4U+b6nLgYeKxUxyjqczugMevTw8HKKxiu8Qpy4U65J+9ZSXS4lv/////8AAAAB//////////8AAAABAAAACYT3EZfkxPxdFqk/tnQn8jJN2OYvIcbqw7cAaDBmAjEAhszsRN2RAPaEgspAJwZYi0LcrM+8glcTL3HwNlzUHEkd75YGVKb/UNAElxXU6IKCAjEAmiw4LPFwAJ6ex2VwIIo++injUUHa1BfiF2HMpqnB5jruGCk3KxS64h0NvdPco6nW',
        commitment: '8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcoo=',
        'content-encryption-key':
          'o2yaJSa81QOYkfWaMhtLntiLLyB3Zfn6b+VifPwBEJ8=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: null,
        footer:
          'AGgwZgIxAIbM7ETdkQD2hILKQCcGWItC3KzPvIJXEy9x8DZc1BxJHe+WBlSm/1DQBJcV1OiCggIxAJosOCzxcACensdlcCCKPvop41FB2tQX4hdhzKapweY67hgpNysUuuIdDb3T3KOp1g==',
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJhPcRl+TE/F0WqT+2dCfyMk3Y5i8hxurDtw==',
        ],
        header:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFJv9+79usIu0JHDLwIBEIA7SELzODxUMVbIbIzq4Bxlq5VgO5IByEOFWGi+Q+NxyubE2cwXwVLptW6y/jiLn6CGrDaBzxuthwHgxmEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFGVND+QpXSW67k+5gIBEIA7Lm792H0cZeQGH0D1MXjYnkOdjSMRSCSjU9nmMwEuOdr16kYAXBul9dY4KpWyRNTfrWJxfoEZh4uldlcCAAAQAPGxXJin3r+Gkr4U+b6nLgYeKxUxyjqczugMevTw8HKKxiu8Qpy4U65J+9ZSXS4lvw==',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '11. Key = example, Message ID = example (signed)',
      },
      {
        ciphertext:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzWRW49EX50QiQO8gsCARCAO5sgMFpr76NxknbZ8CCeup3xNPeF2Mm7Fm0l17+Le0DdI8MBujB9lyGmQWMWIXq5URWbHKLN7sqiM2yiAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyXAus4K5pnm0NpcJ8CARCAO0HKCnxolKBLsbqRPh/WaXxQi1VkJoz/oOVfL4+IFQymTsgKMGgHtFG77hngnoSJQyFPo6b/sMuN4KVKAgAAEAC0UBWiNYSJJvXRl/IXIBh0uo/DOGcPO1rP+V/sOGmM+bZERA+G8H4wcefWYWZ8dv7/////AAAAAf//////////AAAAAQAAAAkgsJoIIYNmoGTtuNrrNcRdC3nxmJaY+Bhu',
        commitment: 'tFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPk=',
        'content-encryption-key':
          'iFGOJpIlmjhVGVThuhE5JZtme0m470naJ3PwCG6oIs0=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {},
        exception: 'EXCEPTION: Invalid commitment',
        frames: [],
        header:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAAAACAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAgB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzWRW49EX50QiQO8gsCARCAO5sgMFpr76NxknbZ8CCeup3xNPeF2Mm7Fm0l17+Le0DdI8MBujB9lyGmQWMWIXq5URWbHKLN7sqiM2yiAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS81OTBmZDc4MS1kZGRlLTQwMzYtYWJlYy0zZTFhYjVhNWQyYWQApwEBAgB4IDgBgT3DGKHrXsN2bi23PO+MOMGydcgwgWav8w1SQk0AAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyXAus4K5pnm0NpcJ8CARCAO0HKCnxolKBLsbqRPh/WaXxQi1VkJoz/oOVfL4+IFQymTsgKMGgHtFG77hngnoSJQyFPo6b/sMuN4KVKAgAAEAC0UBWiNYSJJvXRl/IXIBh0uo/DOGcPO1rP+V/sOGmM+bZERA+G8H4wcefWYWZ8dv4=',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: false,
        'keyring-type': 'aws-kms',
        comment: '12. Two different plaintext data keys, same ciphertext',
      },
      {
        ciphertext:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDBJwQx7rLsF9SMURIgIBEIA76C0ub3htb4Bo0ZgIAoYSRzahiRunNMjvEfZ4oAUq0v6q7BQeeZXFuH0DycxuIwJuaftxZDUR6GEPfA8AB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFCRxguNQerLwoT9TQIBEIA7a9HTYxjgD8GssZNegRz3dwDmNp4NGohmVxI3wwwL1ZxJzSIkwsuwKobQbbNWH149c0fhZyHJX5dk3OoCAAAQALRQFaI1hIkm9dGX8hcgGHS6j8M4Zw87Ws/5X+w4aYz5UtBXqCzIpb8Cd4/WZwbHh/////8AAAAB//////////8AAAABAAAACYedXbtB+YnSiC8XC2WPDytoXd+hEH9zWv8AaDBmAjEAuhsI42YXIDtHJV9QNXWxh1QefwdH8yjcz1ewdCJKHrLFpmvCy5vErQduqGRXSotVAjEAvQNjxDDpDGRjictnjev+3slPy927Jr0SXs7xa/AslIsZHJNI/WQrPc7KVq6DzKKT',
        commitment: 'tFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPk=',
        'content-encryption-key':
          'Mz6CgFku++S+d3kVoozSOiJXpLqaz5m8ClDYGchHsZY=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: 'EXCEPTION: Invalid commitment',
        footer:
          'AGgwZgIxALobCONmFyA7RyVfUDV1sYdUHn8HR/Mo3M9XsHQiSh6yxaZrwsubxK0HbqhkV0qLVQIxAL0DY8Qw6QxkY4nLZ43r/t7JT8vduya9El7O8WvwLJSLGRyTSP1kKz3Oylaug8yikw==',
        frames: [],
        header:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFoR0N4RmM2T3M3aTYydXppMEdKeTR4TmJmY0M5UVRzUWhkaW9PaExISklBdXFiWmlPSmhoQjEvQW95VEwrMU9jZz09AAIAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQECAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDBJwQx7rLsF9SMURIgIBEIA76C0ub3htb4Bo0ZgIAoYSRzahiRunNMjvEfZ4oAUq0v6q7BQeeZXFuH0DycxuIwJuaftxZDUR6GEPfA8AB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5LzU5MGZkNzgxLWRkZGUtNDAzNi1hYmVjLTNlMWFiNWE1ZDJhZACnAQECAHggOAGBPcMYoetew3ZuLbc874w4wbJ1yDCBZq/zDVJCTQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFCRxguNQerLwoT9TQIBEIA7a9HTYxjgD8GssZNegRz3dwDmNp4NGohmVxI3wwwL1ZxJzSIkwsuwKobQbbNWH149c0fhZyHJX5dk3OoCAAAQALRQFaI1hIkm9dGX8hcgGHS6j8M4Zw87Ws/5X+w4aYz5UtBXqCzIpb8Cd4/WZwbHhw==',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: false,
        'keyring-type': 'aws-kms',
        comment:
          '13. Two different plaintext data keys, same ciphertext (signed)',
      },
      {
        ciphertext:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMVS2kQTl1wrYLE2eLAgEQgDulTL6UW+E6FTj+tivbEgzVQCko4XyfLCHO9p6+XhhzZ4ASQdB+InX3zlUO0nzvo6ncpznnFwucVziULgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM3CmTGX0yeaiG9NrQAgEQgDsnrSa/wp3e/eyjabdqfNOdRCgPRfrJg+bSSzs6Y8WogxrrXuCdv/Gxd/tpoGgrfckTXXAvDyzh2snYXAIAABAAApfij7czGOoR2HlxWsLApRGgoK8GT9zcTHLZllYHeIL5z/RijnIgTxn9phSilA70/////wAAAAH//////////wAAAAEAAAAJS+cGlK1P9Uok1Rn7XbeiPqIj9/NYhB4/cQ==',
        commitment: 'Apfij7czGOoR2HlxWsLApRGgoK8GT9zcTHLZllYHeII=',
        'content-encryption-key':
          '4zt1+EPrf/1X9lyHGwI9TaX4KF6nMIZLK6BTRzsHkUc=',
        'decrypted-dek': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
        },
        exception: null,
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJS+cGlK1P9Uok1Rn7XbeiPqIj9/NYhB4/cQ==',
        ],
        header:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMVS2kQTl1wrYLE2eLAgEQgDulTL6UW+E6FTj+tivbEgzVQCko4XyfLCHO9p6+XhhzZ4ASQdB+InX3zlUO0nzvo6ncpznnFwucVziULgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM3CmTGX0yeaiG9NrQAgEQgDsnrSa/wp3e/eyjabdqfNOdRCgPRfrJg+bSSzs6Y8WogxrrXuCdv/Gxd/tpoGgrfckTXXAvDyzh2snYXAIAABAAApfij7czGOoR2HlxWsLApRGgoK8GT9zcTHLZllYHeIL5z/RijnIgTxn9phSilA70',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '14. Key = zero, Message ID = example (with AAD)',
      },
      {
        ciphertext:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlwADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlRVHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMlgzxMfOVccgo/NfWAgEQgDuBa8xMNPel0q7fr4r9y9cKoeaaxqo5vLVr/KNnDbzr13J3Edl70FJhu9iuS3E9Ed81jwt8FeIntzPfuQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMiz3Umk1/gWN+lSq5AgEQgDvGK8/b7k6VRkOHOwisVDZilScjgbNNHNWnPJjo7NKm2/8t///KTjL/QJ/zD5cLsEInvsyltBX9jEd83gIAABAAApfij7czGOoR2HlxWsLApRGgoK8GT9zcTHLZllYHeIIg5X2rC+bMh/YSXh8AcrNA/////wAAAAH//////////wAAAAEAAAAJBjj1QFH18attIsarBYX+AAvXtzBNHXwDkwBnMGUCMQC3jREI99riv0SYM2G3dYMvA26KOHM/f7lhd6VQdM0MX+fHo/LfTEanr2AW9UlustkCMCpX/x8S84qJeTQbnTS0OCEvSjRCWluK4xqnSTc2PvZiOTALHUVBTkvRxBRnaUPa/g==',
        commitment: 'Apfij7czGOoR2HlxWsLApRGgoK8GT9zcTHLZllYHeII=',
        'content-encryption-key':
          'JsOW8DkFqoSmowhVoHjl5YhgMFWqtt8qluHB5vMtH7Y=',
        'decrypted-dek': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: null,
        footer:
          'AGcwZQIxALeNEQj32uK/RJgzYbd1gy8Dboo4cz9/uWF3pVB0zQxf58ej8t9MRqevYBb1SW6y2QIwKlf/HxLziol5NBudNLQ4IS9KNEJaW4rjGqdJNzY+9mI5MAsdRUFOS9HEFGdpQ9r+',
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJBjj1QFH18attIsarBYX+AAvXtzBNHXwDkw==',
        ],
        header:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlwADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlRVHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMlgzxMfOVccgo/NfWAgEQgDuBa8xMNPel0q7fr4r9y9cKoeaaxqo5vLVr/KNnDbzr13J3Edl70FJhu9iuS3E9Ed81jwt8FeIntzPfuQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMiz3Umk1/gWN+lSq5AgEQgDvGK8/b7k6VRkOHOwisVDZilScjgbNNHNWnPJjo7NKm2/8t///KTjL/QJ/zD5cLsEInvsyltBX9jEd83gIAABAAApfij7czGOoR2HlxWsLApRGgoK8GT9zcTHLZllYHeIIg5X2rC+bMh/YSXh8AcrNA',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '15. Key = zero, Message ID = example (signed, with AAD)',
      },
      {
        ciphertext:
          'AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMFEBnKyt3QstLVqt+AgEQgDvjFgXze5zC18mw1EL22Sk1L9s2x/d/yyKUFVcqcxsIN0YBh9nOUkMji/KbaroJticmBBH5iVuC58W7CAAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMpstDQzF757dbNzujAgEQgDtMFvMf2MmJumFtDnpVae1UIZqEhrFGIgtRDd/BVPeA3KZA+HzImTd0bNiOnL6flxyITvnjMkXAstQa3wIAABAAQoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZJzgj4W/ZtkD2K6nrgp64FH/////wAAAAH//////////wAAAAEAAAAJfUPqTiD+hJarwoj8u6zgN+nUJ8sjhoOOtw==',
        commitment: 'QoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZI=',
        'content-encryption-key':
          'GQvu4IjcA/2Yfpk1GYkuT/7ZBOlzHYuwVvvrEfVOfXw=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
        },
        exception: null,
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJfUPqTiD+hJarwoj8u6zgN+nUJ8sjhoOOtw==',
        ],
        header:
          'AgR4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMFEBnKyt3QstLVqt+AgEQgDvjFgXze5zC18mw1EL22Sk1L9s2x/d/yyKUFVcqcxsIN0YBh9nOUkMji/KbaroJticmBBH5iVuC58W7CAAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMpstDQzF757dbNzujAgEQgDtMFvMf2MmJumFtDnpVae1UIZqEhrFGIgtRDd/BVPeA3KZA+HzImTd0bNiOnL6flxyITvnjMkXAstQa3wIAABAAQoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZJzgj4W/ZtkD2K6nrgp64FH',
        'message-id': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '16. Key = example, Message ID = zero (with AAD)',
      },
      {
        ciphertext:
          'AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlwADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlRVHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM5vYU7k2tK4Y4ChgDAgEQgDu7X3F084Gf5T+8/cP+Qge/+xj8lZN95hogWxYwC/HA649wqOHc2dvQeP0rc7OJIUj8QwmCcITyAWvRXgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMbxIh5bCSDVpF64zaAgEQgDsKuqZd6LSW4WtYmeQcydeqQbxnYXzhDlSla6QNcknXuOaACDsonsrh6+0tk7Z1OOA0Jxbrcx8oojE0WgIAABAAQoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZKuxbySIS3cRk6BGotnokRl/////wAAAAH//////////wAAAAEAAAAJy/kcnBqVkxNJQMiH1nkw2v6oDuCcyofEzQBnMGUCMQCmRHBH53c9klyofyrrze8i/Al0AW4K2/3lJF1lc7yV43y2FI1jOByqzsEvu4NjYTgCMDUiSCmLWNOZUdLhGzA7+6q3al2b0eDfV/zpsIKZrQPZccRftNTbxR/m1Wo7udndPg==',
        commitment: 'QoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZI=',
        'content-encryption-key':
          '61/Wu0/yvuQ2KHTjUpHpSIPSouZb/AtU8jl2HtEmjIs=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: null,
        footer:
          'AGcwZQIxAKZEcEfndz2SXKh/KuvN7yL8CXQBbgrb/eUkXWVzvJXjfLYUjWM4HKrOwS+7g2NhOAIwNSJIKYtY05lR0uEbMDv7qrdqXZvR4N9X/OmwgpmtA9lxxF+01NvFH+bVaju52d0+',
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJy/kcnBqVkxNJQMiH1nkw2v6oDuCcyofEzQ==',
        ],
        header:
          'AgV4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlwADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlRVHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM5vYU7k2tK4Y4ChgDAgEQgDu7X3F084Gf5T+8/cP+Qge/+xj8lZN95hogWxYwC/HA649wqOHc2dvQeP0rc7OJIUj8QwmCcITyAWvRXgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMbxIh5bCSDVpF64zaAgEQgDsKuqZd6LSW4WtYmeQcydeqQbxnYXzhDlSla6QNcknXuOaACDsonsrh6+0tk7Z1OOA0Jxbrcx8oojE0WgIAABAAQoChYbw/b0wnt9pA+NkCz4+2pLAEqD9U9NjeGs+ZaZKuxbySIS3cRk6BGotnokRl',
        'message-id': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '17. Key = example, Message ID = zero (signed, with AAD)',
      },
      {
        ciphertext:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMA0otLRQxvR8Ud+pKAgEQgDvVR2YZbiRGnzk9VHphC2z0gf/3fnC856VJsjDHyXfeveuOAOg8lHBR2yqcbV6kFafqsLGuhoNM7kVkhAAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM+7tKI00Bt/e3ZvEiAgEQgDtVAzyv+65kZInUtQjH5uEkHKcMGXPDWMGjaGo5u8AEVGkwM+Sph6+lykd21OT67IqUt6g25v8O0+PBSwIAABAA8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcopiz5Sh5k0vkhhnD960r/31/////wAAAAH//////////wAAAAEAAAAJyHiCZSD8Gxa3Btt9ilhrITCfftYCrm5ZzA==',
        commitment: '8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcoo=',
        'content-encryption-key':
          'o+avOr85YWbGFlh4G5kA5I8wBW4qre0d5/+BsW/uOis=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
        },
        exception: null,
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJyHiCZSD8Gxa3Btt9ilhrITCfftYCrm5ZzA==',
        ],
        header:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMA0otLRQxvR8Ud+pKAgEQgDvVR2YZbiRGnzk9VHphC2z0gf/3fnC856VJsjDHyXfeveuOAOg8lHBR2yqcbV6kFafqsLGuhoNM7kVkhAAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM+7tKI00Bt/e3ZvEiAgEQgDtVAzyv+65kZInUtQjH5uEkHKcMGXPDWMGjaGo5u8AEVGkwM+Sph6+lykd21OT67IqUt6g25v8O0+PBSwIAABAA8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcopiz5Sh5k0vkhhnD960r/31',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '18. Key = example, Message ID = example (with AAD)',
      },
      {
        ciphertext:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlwADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlRVHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMxOjP1UAeC+vE5J1fAgEQgDvgHwPc3KpNStTjhawDEa7Z5UDCnKwSH5KaTYT0Qbnu2o3RVgjLQxsa5FjdBUzi3lusy2g4HRMeGgk5QQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKTHgS3LLlQH3xP7EAgEQgDu+iRlWxVymazFlhKAAaNkQhpZzxyljqYBgctCjsmVwSfic4+VH5gOLsLyNUC0JwqNHTH5+hcphGVgXTQIAABAA8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcormGII0al4n1z8nUbSVXezJ/////wAAAAH//////////wAAAAEAAAAJhPcRl+TE/F0WqT+2dCfyMk3Y5i8hxurDtwBoMGYCMQCES2bdqjxadCcKb/NgzQ+KxCXix0VBh0mJwKyyUXvwjUFoGJkecdswSXhPiYO7EocCMQDWPwhemHv5ObNVjv9iEmTF5wghBIi3aYeY4N3QQRcPtkuCdcaqKRR3u8VzZsFR9eg=',
        commitment: '8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcoo=',
        'content-encryption-key':
          'o2yaJSa81QOYkfWaMhtLntiLLyB3Zfn6b+VifPwBEJ8=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: null,
        footer:
          'AGgwZgIxAIRLZt2qPFp0Jwpv82DND4rEJeLHRUGHSYnArLJRe/CNQWgYmR5x2zBJeE+Jg7sShwIxANY/CF6Ye/k5s1WO/2ISZMXnCCEEiLdph5jg3dBBFw+2S4J1xqopFHe7xXNmwVH16A==',
        frames: [
          '/////wAAAAH//////////wAAAAEAAAAJhPcRl+TE/F0WqT+2dCfyMk3Y5i8hxurDtw==',
        ],
        header:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlwADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlRVHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMxOjP1UAeC+vE5J1fAgEQgDvgHwPc3KpNStTjhawDEa7Z5UDCnKwSH5KaTYT0Qbnu2o3RVgjLQxsa5FjdBUzi3lusy2g4HRMeGgk5QQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKTHgS3LLlQH3xP7EAgEQgDu+iRlWxVymazFlhKAAaNkQhpZzxyljqYBgctCjsmVwSfic4+VH5gOLsLyNUC0JwqNHTH5+hcphGVgXTQIAABAA8bFcmKfev4aSvhT5vqcuBh4rFTHKOpzO6Ax69PDwcormGII0al4n1z8nUbSVXezJ',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '19. Key = example, Message ID = example (signed, with AAD)',
      },
      {
        ciphertext:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMa0HbVm3pJUfxLRYYAgEQgDuR/OmD0OFsgzBNOppbGC20b+e4iMYVRb2/MocrN8fFc+/lC6ERZzLFh90CO4QEcKKfelssXufLxx7qLAAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM4PTMwlCPPqF2SFfOAgEQgDtHXTkMqX6j3VPqV9RxZjlPEGGB3twqK2eX8g2kAKYIObPvJNZvsDHR0ge8k0U9eQ7WDBwCwyaNsDpCiwIAABAAtFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPlwqyAp6svYC2BmtqRuFAlr/////wAAAAH//////////wAAAAEAAAAJILCaCCGDZqBk7bja6zXEXQt58ZiWmPgYbg==',
        commitment: 'tFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPk=',
        'content-encryption-key':
          'iFGOJpIlmjhVGVThuhE5JZtme0m470naJ3PwCG6oIs0=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
        },
        exception: 'EXCEPTION: Invalid commitment',
        frames: [],
        header:
          'AgR4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMa0HbVm3pJUfxLRYYAgEQgDuR/OmD0OFsgzBNOppbGC20b+e4iMYVRb2/MocrN8fFc+/lC6ERZzLFh90CO4QEcKKfelssXufLxx7qLAAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM4PTMwlCPPqF2SFfOAgEQgDtHXTkMqX6j3VPqV9RxZjlPEGGB3twqK2eX8g2kAKYIObPvJNZvsDHR0ge8k0U9eQ7WDBwCwyaNsDpCiwIAABAAtFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPlwqyAp6svYC2BmtqRuFAlr',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: false,
        'keyring-type': 'aws-kms',
        comment:
          '20. Two different plaintext data keys, same ciphertext (with AAD)',
      },
      {
        ciphertext:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlwADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlRVHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMrp6QFLdmNOISqjdzAgEQgDuCXiJsMNKTfNWmYDoMnJcI+oRQBeIl0d1pZBu5pBxGgS6chIfLVbcmweuUZDk0TCJLah7PVv3JfTSpLQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM1QFgfyGcwGCV+dGjAgEQgDvI+3I0/U4wng4yWrV4RYtozOmW+lgipeTBRm3+6icDcD0A/8gzF6t4LjzgNm812nbcazbYazNAvd0xuwIAABAAtFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPlwgv4XNIzljFNfv4FZni21/////wAAAAH//////////wAAAAEAAAAJh51du0H5idKILxcLZY8PK2hd36EQf3Na/wBnMGUCMQCRoSvXwlzNpXaMoH3xaSwRKxekj1t8GpfiULRl/KEjC6gRIWYcxV2zmMy1DCqwC7sCMHVZkw/zs6sbyWcMPz1Rsl6kM2lSm8BWls9ZIqw7yF3I4fob1sdjxu0iIRwYrtSlSg==',
        commitment: 'tFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPk=',
        'content-encryption-key':
          'Mz6CgFku++S+d3kVoozSOiJXpLqaz5m8ClDYGchHsZY=',
        'decrypted-dek': 'Sfdon2EodFWiGY6ITvIDJZXhzKZPj2IQCi+1x/tw2ho=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
          'aws-crypto-public-key':
            'AhGCxFc6Os7i62uzi0GJy4xNbfcC9QTsQhdioOhLHJIAuqbZiOJhhB1/AoyTL+1Ocg==',
        },
        exception: 'EXCEPTION: Invalid commitment',
        footer:
          'AGcwZQIxAJGhK9fCXM2ldoygffFpLBErF6SPW3wal+JQtGX8oSMLqBEhZhzFXbOYzLUMKrALuwIwdVmTD/OzqxvJZww/PVGyXqQzaVKbwFaWz1kirDvIXcjh+hvWx2PG7SIhHBiu1KVK',
        frames: [],
        header:
          'AgV4PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVsAlwADAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAFWF3cy1jcnlwdG8tcHVibGljLWtleQBEQWhHQ3hGYzZPczdpNjJ1emkwR0p5NHhOYmZjQzlRVHNRaGRpb09oTEhKSUF1cWJaaU9KaGhCMS9Bb3lUTCsxT2NnPT0AAgAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQIAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMrp6QFLdmNOISqjdzAgEQgDuCXiJsMNKTfNWmYDoMnJcI+oRQBeIl0d1pZBu5pBxGgS6chIfLVbcmweuUZDk0TCJLah7PVv3JfTSpLQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvNTkwZmQ3ODEtZGRkZS00MDM2LWFiZWMtM2UxYWI1YTVkMmFkAKcBAQIAeCA4AYE9wxih617Ddm4ttzzvjDjBsnXIMIFmr/MNUkJNAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM1QFgfyGcwGCV+dGjAgEQgDvI+3I0/U4wng4yWrV4RYtozOmW+lgipeTBRm3+6icDcD0A/8gzF6t4LjzgNm812nbcazbYazNAvd0xuwIAABAAtFAVojWEiSb10ZfyFyAYdLqPwzhnDztaz/lf7DhpjPlwgv4XNIzljFNfv4FZni21',
        'message-id': 'PKWpyXOBmk4yDyakq0VRlXuStoPoaQ0n0tO1i/9LdVs=',
        'plaintext-frames': ['testing12'],
        status: false,
        'keyring-type': 'aws-kms',
        comment:
          '21. Two different plaintext data keys, same ciphertext (signed, with AAD)',
      },
      {
        ciphertext:
          'AgR4ZzjLWV5kAQKVlXj57IcJa1iEqTYVzYLoqG8PRUdtGnEAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzm/W4IEwyw1XGMDx8CARCAOzWxBU81iv0uAE17I6C3HxgVlMZm2br9GAktcyJ5IgZKA6N8MLzLAmbDoMb1HxJEKkb8F49QTArCUhX7AgAAEADreoUk9jDTH/FR/nDtTKFjBD6r2ipZhT5LsJtgx2rbJGBYOeO5FCZSGlsZTIsoNDL/////AAAAAQAAAAAAAAAAAAAAAQAAAAm5gmDN/oEFl97JI39GIyXlS3CudSGOWm8p',
        commitment: '63qFJPYw0x/xUf5w7UyhYwQ+q9oqWYU+S7CbYMdq2yQ=',
        'decrypted-dek': '4aY8MK4AdgTXDgz7DXIUfOZ81MR7/v8Vh1qS4hha4U4=',
        'encryption-context': {},
        exception: null,
        header:
          'AgR4ZzjLWV5kAQKVlXj57IcJa1iEqTYVzYLoqG8PRUdtGnEAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAzm/W4IEwyw1XGMDx8CARCAOzWxBU81iv0uAE17I6C3HxgVlMZm2br9GAktcyJ5IgZKA6N8MLzLAmbDoMb1HxJEKkb8F49QTArCUhX7AgAAEADreoUk9jDTH/FR/nDtTKFjBD6r2ipZhT5LsJtgx2rbJGBYOeO5FCZSGlsZTIsoNDI=',
        'message-id': 'ZzjLWV5kAQKVlXj57IcJa1iEqTYVzYLoqG8PRUdtGnE=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '22. Simple JS encrypt',
      },
      {
        ciphertext:
          'AgR4BiIWGA4lhe6nW3EBq9ri5hyuIcvnhaWt6s6yP70JnwQAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM4qQYbJbU6HvDqgEBAgEQgDsSqi/xWCa5VP0Ax1s+G6AIZ3GkNE2kR2WzLYXpA9HCZ4pny25nD5vguvGtbdKGR4TlpTPkxvUTa+LHNQIAABAAbzal1s5Ht+XmPGs+lzwMTU3VsVKI1h73jcUgz4G30oAmkkGJNdjmZFflISSBirPH/////wAAAAEAAAAAAAAAAAAAAAEAAAAJ5LRWdzEYzFurmIpJRc9PzENBizW3+v7/Qg==',
        commitment: 'bzal1s5Ht+XmPGs+lzwMTU3VsVKI1h73jcUgz4G30oA=',
        'decrypted-dek': '/tCswbBkCYGs0DgkPDm775OnlQXO6N8zWLMTuHvPrqg=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
        },
        exception: null,
        header:
          'AgR4BiIWGA4lhe6nW3EBq9ri5hyuIcvnhaWt6s6yP70JnwQAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM4qQYbJbU6HvDqgEBAgEQgDsSqi/xWCa5VP0Ax1s+G6AIZ3GkNE2kR2WzLYXpA9HCZ4pny25nD5vguvGtbdKGR4TlpTPkxvUTa+LHNQIAABAAbzal1s5Ht+XmPGs+lzwMTU3VsVKI1h73jcUgz4G30oAmkkGJNdjmZFflISSBirPH',
        'message-id': 'BiIWGA4lhe6nW3EBq9ri5hyuIcvnhaWt6s6yP70JnwQ=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '23. Simple JS encrypt (with AAD)',
      },
      {
        ciphertext:
          'AgR4iCL3obBFAgl2H4KE8R96eNgBjLqFzwofaagV/SF1UJgAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMFUkHCQBWWWqXIwgfAgEQgDt+DtsGGoRXX/c2o6u8WUX7EPdRCBuYBjKTEexmgld+jqfu9ogp+XVs/lEPCnThJE7lZ26ufBNtuZpNZwIAAAABW3KhrYH9MFe3n+Js+v5arMzHmH58k/3TjhBfn28QENxyh41IeBjszPCSS9P1WjiFAAAAAQAAAAAAAAAAAAAAATFhtmleghwYLnacJo9PvJ8zAAAAAgAAAAAAAAAAAAAAAqN1bVJRZ7u4SxGPLFCAaUCIAAAAAwAAAAAAAAAAAAAAAxHeThX1MRHvZDw6RRc0GbaMAAAABAAAAAAAAAAAAAAABLxdlMXxvjmARlkmTHYjH0MaAAAABQAAAAAAAAAAAAAABYpcAmbgJbPAei4O+8e/7rC8AAAABgAAAAAAAAAAAAAABnylrtV/x7G9ll5XX7+l5qPkAAAABwAAAAAAAAAAAAAAB92sSPXn8rtFFw/H8zMcax38AAAACAAAAAAAAAAAAAAACOg8ggvUao5tOL/CqpTEdNHpAAAACQAAAAAAAAAAAAAACSaxo/DM3P6NKU3BPlZAubgR/////wAAAAoAAAAAAAAAAAAAAAoAAAAAhh5ydHx1RXNFYRN5zY0jhg==',
        commitment: 'W3KhrYH9MFe3n+Js+v5arMzHmH58k/3TjhBfn28QENw=',
        'decrypted-dek': '0fdi6NBvUeXX+pmFX6SUir0Q7/q5b2cQJJOtJpbWC5Q=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
        },
        exception: null,
        header:
          'AgR4iCL3obBFAgl2H4KE8R96eNgBjLqFzwofaagV/SF1UJgAOgACAAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMFUkHCQBWWWqXIwgfAgEQgDt+DtsGGoRXX/c2o6u8WUX7EPdRCBuYBjKTEexmgld+jqfu9ogp+XVs/lEPCnThJE7lZ26ufBNtuZpNZwIAAAABW3KhrYH9MFe3n+Js+v5arMzHmH58k/3TjhBfn28QENxyh41IeBjszPCSS9P1WjiF',
        'message-id': 'iCL3obBFAgl2H4KE8R96eNgBjLqFzwofaagV/SF1UJg=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '24. JS encrypt (with AAD) 1byte frame',
      },
      {
        ciphertext:
          'AgV4nod6k6U3+hHpc2+9TE2fJvNJYmXxy5HKeGP2976E24wAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFydDRid3dTWVFUdnJpRUJQcWpDVzhWMTdMYkNidHNtb0F4MHpXdTFxa2Nnd0lVUWVOV2RnckJnVWhQTEkxUE9ZQT09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDJpAGhSRmDYszjWV6wIBEIA7uVaaElPbdkhU606jGGVzlu7jtdib9n7IEBMxhTveoM3I7Jx4WeEp5V6PJJVRlYgSaYnWZgd+pyNo7uUCAAAQAEhoaOayTlJx1SbHzfKvoTojWNzxHF2S8tryntZVRRBV13bvyHPyFxkLMXVkCze8V/////8AAAABAAAAAAAAAAAAAAABAAAACTCts6F2Ov1/AGioyQndGwQnZw3UZlO38WoAZjBkAi9JY1EB/YcIGvwbkjfvlzraylN1beJzTZuIKzMWvQAMUPaLe80Szxw/F8p9KPlhKgIxAP/+fRUljLTg5Inw7LeAyW8oFBQNuSgmdIAZavogUFU+e1A+kQtvWdHUiLA0DgElQg==',
        commitment: 'SGho5rJOUnHVJsfN8q+hOiNY3PEcXZLy2vKe1lVFEFU=',
        'decrypted-dek': 'rnlg7ipPE0mbNg7SiAf039ey9BjswFQyHOPiLp5u1V4=',
        'encryption-context': {
          'aws-crypto-public-key':
            'Art4bwwSYQTvriEBPqjCW8V17LbCbtsmoAx0zWu1qkcgwIUQeNWdgrBgUhPLI1POYA==',
        },
        exception: null,
        header:
          'AgV4nod6k6U3+hHpc2+9TE2fJvNJYmXxy5HKeGP2976E24wAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFydDRid3dTWVFUdnJpRUJQcWpDVzhWMTdMYkNidHNtb0F4MHpXdTFxa2Nnd0lVUWVOV2RnckJnVWhQTEkxUE9ZQT09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDJpAGhSRmDYszjWV6wIBEIA7uVaaElPbdkhU606jGGVzlu7jtdib9n7IEBMxhTveoM3I7Jx4WeEp5V6PJJVRlYgSaYnWZgd+pyNo7uUCAAAQAEhoaOayTlJx1SbHzfKvoTojWNzxHF2S8tryntZVRRBV13bvyHPyFxkLMXVkCze8Vw==',
        'message-id': 'nod6k6U3+hHpc2+9TE2fJvNJYmXxy5HKeGP2976E24w=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '25. Simple JS encrypt (signed)',
      },
      {
        ciphertext:
          'AgV4SRXxd2NDKOwAK7EYmcVdoN70/a4cd0UQxPLBy8QlCBcAlwADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF2VE4rUkR2UzJISG1URk1KZCtGNFNMMGl0MXdvVTZOL0tSU2FQVng2WWREdkQrZVlvSmZiT0JNcnh3MnNqM3ZkQT09AAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMLtjZcR8parum7ZR3AgEQgDv09dkEH/ruNg2NegEnyE70usveM7797/b0IuEMu+0SDqES0zViAvGONZJsV67nHYbNPrs8lsPb9AwCCAIAABAAkbBHwH7I84SFz+s/eagR9kB1Oo1VEJLCWf+8p9CEdvS7eYYjthsdoDEufe8ssndV/////wAAAAEAAAAAAAAAAAAAAAEAAAAJSV1n7Qqi45oXfU2nLU8ZNKAsGlCjF62apQBoMGYCMQC7CzoB18g7LBHxmbaC/TscsTkeSIoztKh9LzWrdny6AX5KXedpKkj957mlLFJ7xvkCMQC/BpMw8W6hnEa8yQyJNRtKvg8i9UhbV2tJ7kGzpE0nUNcsUn/1BwR1AHYv0MtLIy4=',
        commitment: 'kbBHwH7I84SFz+s/eagR9kB1Oo1VEJLCWf+8p9CEdvQ=',
        'decrypted-dek': 'RtABha+g0NdkwR43yxTAIFHmVm3dN2UuYywpNUarrF0=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
          'aws-crypto-public-key':
            'AvTN+RDvS2HHmTFMJd+F4SL0it1woU6N/KRSaPVx6YdDvD+eYoJfbOBMrxw2sj3vdA==',
        },
        exception: null,
        header:
          'AgV4SRXxd2NDKOwAK7EYmcVdoN70/a4cd0UQxPLBy8QlCBcAlwADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF2VE4rUkR2UzJISG1URk1KZCtGNFNMMGl0MXdvVTZOL0tSU2FQVng2WWREdkQrZVlvSmZiT0JNcnh3MnNqM3ZkQT09AAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMLtjZcR8parum7ZR3AgEQgDv09dkEH/ruNg2NegEnyE70usveM7797/b0IuEMu+0SDqES0zViAvGONZJsV67nHYbNPrs8lsPb9AwCCAIAABAAkbBHwH7I84SFz+s/eagR9kB1Oo1VEJLCWf+8p9CEdvS7eYYjthsdoDEufe8ssndV',
        'message-id': 'SRXxd2NDKOwAK7EYmcVdoN70/a4cd0UQxPLBy8QlCBc=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '26. Simple JS encrypt (signed with AAD)',
      },
      {
        ciphertext:
          'AgV41wCZ4BqY2Cx0CxGm8/koQpqTRMu8nP1ntIHLGLxB9X4AlwADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFuaEdPcGM4TVM1NFdWTjJteTB3NHhaOVk1M1h5RTRIeFpBSUJPTlRrYW9UT3NOU0xJVEJVRXVVVmNnVjJOK0ZsZz09AAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMpMUYWP285UGw/AmCAgEQgDtmuzcaMPiY+zoGW/HupbJJOTicJEzFGYqz8VD/uYbapQixhJMYJAfVDU6N7f/tsMBckKE1JAAm4/NpfAIAAAABGDzmHkvsXZw/S51Z2IwF5tXFhiM47NTo+UiRotqRuOAKAW9WKd5x2ONAuWrzDDcUAAAAAQAAAAAAAAAAAAAAAYtOnuOM43FbAh8YQX42NmIyAAAAAgAAAAAAAAAAAAAAAm2fsrBCSB0FgjPZYIzgMTUdAAAAAwAAAAAAAAAAAAAAA1bydLuJbuThvFatZ5Lzm4AzAAAABAAAAAAAAAAAAAAABDokA1/+j4d+3wCNTYy6iIVjAAAABQAAAAAAAAAAAAAABYc0mcYJjilk8+MwijGHFtE6AAAABgAAAAAAAAAAAAAABqvmulDqkXcIBKNGBM/awn4+AAAABwAAAAAAAAAAAAAAB8TbxRI0xBDBBUkGOc1l4e53AAAACAAAAAAAAAAAAAAACNPZlcnytPsFK2iqj/JV9LU7AAAACQAAAAAAAAAAAAAACeLMC3KMhVfzTAGG4q9Yclp3/////wAAAAoAAAAAAAAAAAAAAAoAAAAAIyJHRhgr+RXwWwmgULn3dwBmMGQCMBAuknmnfN782mJM/SB/fXc1x1uwyUsdvjlfSFDP0LX4YfwcXvehapxu/06ciltuHwIwJkbmdd+qrKTupj6UE6JR/ia19qPx3BF8XccN5AyDeKZ5nk/+4q/KfW5+D8inMuV0',
        commitment: 'GDzmHkvsXZw/S51Z2IwF5tXFhiM47NTo+UiRotqRuOA=',
        'decrypted-dek': 'YW6c551XES/jyr5MtVN1vkCG2+wxgxePpDGyk2K871M=',
        'encryption-context': {
          'test-key': 'test value',
          'test-key-2': 'another test example',
          'aws-crypto-public-key':
            'AnhGOpc8MS54WVN2my0w4xZ9Y53XyE4HxZAIBONTkaoTOsNSLITBUEuUVcgV2N+Flg==',
        },
        exception: null,
        header:
          ' AgV41wCZ4BqY2Cx0CxGm8/koQpqTRMu8nP1ntIHLGLxB9X4AlwADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFuaEdPcGM4TVM1NFdWTjJteTB3NHhaOVk1M1h5RTRIeFpBSUJPTlRrYW9UT3NOU0xJVEJVRXVVVmNnVjJOK0ZsZz09AAh0ZXN0LWtleQAKdGVzdCB2YWx1ZQAKdGVzdC1rZXktMgAUYW5vdGhlciB0ZXN0IGV4YW1wbGUAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMpMUYWP285UGw/AmCAgEQgDtmuzcaMPiY+zoGW/HupbJJOTicJEzFGYqz8VD/uYbapQixhJMYJAfVDU6N7f/tsMBckKE1JAAm4/NpfAIAAAABGDzmHkvsXZw/S51Z2IwF5tXFhiM47NTo+UiRotqRuOAKAW9WKd5x2ONAuWrzDDcU',
        'message-id': '1wCZ4BqY2Cx0CxGm8/koQpqTRMu8nP1ntIHLGLxB9X4=',
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment: '27. JS encrypt (signed with AAD) 1byte frame',
      },
      {
        ciphertext:
          'AgR4fhEwYp4uvtSjKKVBRNo8M4cCzGNZCYJlKZ6dNV2TBPEAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyjF8TPWFNeTAVPNiUCARCAOwHa2IwF6OfmFdnZ1thO3nryExnRRrpV6SuDQMcVE4kN7GJSLMjUNKOHWy+tc6w4GJ8YZQPaXh3FZpi5AQAAAACBQTGyBZRrmYgb72ew18KF56PZxUWaw0tTi22YAY/r6oGdS+5h09VRBcpMLGuaDu4AAAAAAAAAAAAAAAEAAAAAAAAAQJIOz+8G3/o/pAvlKSNdtiPli7T/33N3BIOT8XsWqnzSF5JEYpaNdFpKLC6t9zgK6HHBr73ehnL1yHPU3FvWBqeD8QDElTDQ3prt4rUiN8kN',
        commitment: 'gUExsgWUa5mIG+9nsNfCheej2cVFmsNLU4ttmAGP6+o=',
        'message-id': 'fhEwYp4uvtSjKKVBRNo8M4cCzGNZCYJlKZ6dNV2TBPE=',
        header:
          'AgR4fhEwYp4uvtSjKKVBRNo8M4cCzGNZCYJlKZ6dNV2TBPEAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyjF8TPWFNeTAVPNiUCARCAOwHa2IwF6OfmFdnZ1thO3nryExnRRrpV6SuDQMcVE4kN7GJSLMjUNKOHWy+tc6w4GJ8YZQPaXh3FZpi5AQAAAACBQTGyBZRrmYgb72ew18KF56PZxUWaw0tTi22YAY/r6oGdS+5h09VRBcpMLGuaDu4=',
        'decrypted-dek': '5SD48CW8Md8mKuygllS+zJlE5X8mhIqk+5nq3e2lnhU=',
        'encryption-context': {},
        exception: null,
        'plaintext-frames': [
          '28. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; unframed',
        ],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '28. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; unframed',
      },
      {
        ciphertext:
          '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',
        commitment: '/AZuebrDoBhDGw8k3yYnIMXR3n6i8aPh7l0ip3cpFgM=',
        'message-id': 'r4RshhYvCOY/ajQPeb54T49paP2DVvo2PfIXU+3hbTU=',
        header:
          'AgR4r4RshhYvCOY/ajQPeb54T49paP2DVvo2PfIXU+3hbTUAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyEE40xvDMtH0/MW9YCARCAO40maS/hEokvZST+ZLwNSRl4kFobypfiG9PrkivJeUZfuKYL3biHGamGxbcO0GhiuVNIUpLTnOjqD8g/AgAAAAH8Bm55usOgGEMbDyTfJicgxdHefqLxo+HuXSKndykWA8gq5RRBe5igAl5sT7DzowY=',
        'decrypted-dek': 'wElcw7jHSJ5f/aQpQyxuodFP3OgmxBnO1LNZPn+QU2U=',
        'encryption-context': {},
        exception: null,
        'plaintext-frames': [
          '2',
          '9',
          '.',
          ' ',
          '[',
          'C',
          ' ',
          'E',
          'S',
          'D',
          'K',
          ']',
          ' ',
          'a',
          'l',
          'g',
          '=',
          'A',
          'L',
          'G',
          '_',
          'A',
          'E',
          'S',
          '2',
          '5',
          '6',
          '_',
          'G',
          'C',
          'M',
          '_',
          'H',
          'K',
          'D',
          'F',
          '_',
          'S',
          'H',
          'A',
          '5',
          '1',
          '2',
          '_',
          'C',
          'O',
          'M',
          'M',
          'I',
          'T',
          '_',
          'K',
          'E',
          'Y',
          ';',
          ' ',
          'f',
          'r',
          'a',
          'm',
          'e',
          '_',
          's',
          'i',
          'z',
          'e',
          '=',
          '1',
        ],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '29. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=1',
      },
      {
        ciphertext:
          'AgR4K3m8tPW6+GZbv2h6l/Zog57SL5sT9o50Bf9FbObk18gAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwHMATBwGsO+itTfXkCARCAO2quKOuXQ1vgTLsWWcF5Xxta5xGkziCmXh3MjZz7fg9Rh9+uM7giP9yGqpLPhws29+QCSDc+U+MjbjvPAgAAABBKcTTOB2n0NhpGIjqX6asWzqnVxGL9ElHDsIADOwl25HBnjqaKG2LS5Yb+aVyMJW4AAAABAAAAAAAAAAAAAAABabtPdgY42AWzHXmW92NiQzrnvQV9OrG3UN89DTZZ/tkAAAACAAAAAAAAAAAAAAACXd1zoo32cOde25/kpfepcMB8JCqFeYQRFlyc0YrKJf0AAAADAAAAAAAAAAAAAAADKLae04FNWjljylpTTZPVdmAMQ2WoHKzMPC1qnsWZHvAAAAAEAAAAAAAAAAAAAAAEBt6stQeuur0FKyYK9bR1K6+sJn/q8wB8gajT1pxb+Xb/////AAAABQAAAAAAAAAAAAAABQAAAAXwamnjgyqZoZJjJMf8KLi4WFC5AzM=',
        commitment: 'SnE0zgdp9DYaRiI6l+mrFs6p1cRi/RJRw7CAAzsJduQ=',
        'message-id': 'K3m8tPW6+GZbv2h6l/Zog57SL5sT9o50Bf9FbObk18g=',
        header:
          'AgR4K3m8tPW6+GZbv2h6l/Zog57SL5sT9o50Bf9FbObk18gAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwHMATBwGsO+itTfXkCARCAO2quKOuXQ1vgTLsWWcF5Xxta5xGkziCmXh3MjZz7fg9Rh9+uM7giP9yGqpLPhws29+QCSDc+U+MjbjvPAgAAABBKcTTOB2n0NhpGIjqX6asWzqnVxGL9ElHDsIADOwl25HBnjqaKG2LS5Yb+aVyMJW4=',
        'decrypted-dek': 'E4ocDFKJ9JGz2dXyOBNqh9atsl6ceVqoftZzhiTAVK8=',
        'encryption-context': {},
        exception: null,
        'plaintext-frames': [
          '30. [C ESDK] alg',
          '=ALG_AES256_GCM_',
          'HKDF_SHA512_COMM',
          'IT_KEY; frame_si',
          'ze=16',
        ],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '30. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=16',
      },
      {
        ciphertext:
          'AgR4gAA7pUhGfkfy82zd66QV7oEpgAY/d0PQv+69MJwcZaQAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAz2OsdsmlWWA/LqJscCARCAO/Zfy5nh0mNvvn4WKkjt6cTqBl/tAmmJKHyxt9orNTGGoTRAyUy4EA5A794sqU0AVXiSP3y4GIcg3GT9AgAABACcuZNYrK2pO/AtSUAL495ZtuouZUHtgi66pbyqaJkJglijsti80CwWoVmBdkCk+2f/////AAAAAQAAAAAAAAAAAAAAAQAAAEdqhQognTmY0tGmRPwKMMi5WhdUab5fEA4aqCR5QaKp9J4JnTdrqepBxkZ1KWjlmiUnqCGyTIPhKhTMTYFztz3cphx85xe1raLWByDQbPSaD/6FOEixwLY=',
        commitment: 'nLmTWKytqTvwLUlAC+PeWbbqLmVB7YIuuqW8qmiZCYI=',
        'message-id': 'gAA7pUhGfkfy82zd66QV7oEpgAY/d0PQv+69MJwcZaQ=',
        header:
          'AgR4gAA7pUhGfkfy82zd66QV7oEpgAY/d0PQv+69MJwcZaQAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAz2OsdsmlWWA/LqJscCARCAO/Zfy5nh0mNvvn4WKkjt6cTqBl/tAmmJKHyxt9orNTGGoTRAyUy4EA5A794sqU0AVXiSP3y4GIcg3GT9AgAABACcuZNYrK2pO/AtSUAL495ZtuouZUHtgi66pbyqaJkJglijsti80CwWoVmBdkCk+2c=',
        'decrypted-dek': 'CcR2nrT/kcO4xJDogk5djrW6fSbjErxmXf9anzG5kSU=',
        'encryption-context': {},
        exception: null,
        'plaintext-frames': [
          '31. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=1024',
        ],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '31. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=1024',
      },
      {
        ciphertext:
          'AgV4L2S0PjlT+XA5n5U65oi/3NDRjFAuzOzfc8ceMbAh5DYAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFzanM1TklJblNoM2RrVmtyQmlxSkhXK2dNVzV5eWx5elNUbVprVUZMOTBiS09kMmdhUUM2N1k4WmpGTktNVmY0Zz09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDEoy6kj/pFN3NU5iXQIBEIA7X7fjiNBdtgeYDNAoe/DcVQVw5rgnJS9VqnSp0KlF0Km8a/ZzXCgYBb00WwTns4vcxq0rZwVL4DkULToBAAAAAJB7d2YxM9LBEXbzT3LVQHP3yotU2Y2n6pLQmYeo8bMe7YU6Q4zMaICWf7u2RP6NQAAAAAAAAAAAAAAAAQAAAAAAAABLCoBohy10UfWSBVipyqTKUw6ur/9jPvsWSww4CaQ7mtjQ+CY9xwO10H6zRIxnq3bR43iYHM8d0clSV4k6dNet1Y2HJt1bFXnuuY3rdAxH/Iee//SvqvVjcOwNsABnMGUCMQCY+AHrGu/0hAy6dWbX+zVTu97+MUfSl8NcMmTNCKhtwcxKHnTQZlFEc7Qzu7A6iDMCMBReZ6xwJp1h8fzYyZ9m50XDwG/jzx/v+lRbGVulEjVdfdWvyYx+GAkNJEEQaBVZwQ==',
        commitment: 'kHt3ZjEz0sERdvNPctVAc/fKi1TZjafqktCZh6jxsx4=',
        'message-id': 'L2S0PjlT+XA5n5U65oi/3NDRjFAuzOzfc8ceMbAh5DY=',
        header:
          'AgV4L2S0PjlT+XA5n5U65oi/3NDRjFAuzOzfc8ceMbAh5DYAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFzanM1TklJblNoM2RrVmtyQmlxSkhXK2dNVzV5eWx5elNUbVprVUZMOTBiS09kMmdhUUM2N1k4WmpGTktNVmY0Zz09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDEoy6kj/pFN3NU5iXQIBEIA7X7fjiNBdtgeYDNAoe/DcVQVw5rgnJS9VqnSp0KlF0Km8a/ZzXCgYBb00WwTns4vcxq0rZwVL4DkULToBAAAAAJB7d2YxM9LBEXbzT3LVQHP3yotU2Y2n6pLQmYeo8bMe7YU6Q4zMaICWf7u2RP6NQA==',
        'decrypted-dek': 'p7jVbJV7IWyZ+VKrPIMcPRU0kdAqQxOtCLDYwuRps84=',
        'encryption-context': {
          'aws-crypto-public-key':
            'Asjs5NIInSh3dkVkrBiqJHW+gMW5yylyzSTmZkUFL90bKOd2gaQC67Y8ZjFNKMVf4g==',
        },
        exception: null,
        'plaintext-frames': [
          '32. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed',
        ],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '32. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed',
      },
      {
        ciphertext:
          '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',
        commitment: 'WBCclfUjcj+DCoc31YFH7CS2i+V5kD4Vwx9krnc8Pgc=',
        'message-id': 'G59FPxp4eCwrZrzjP0zIia9+Xmv+DdaTCNUj9UdyT5U=',
        header:
          'AgV4G59FPxp4eCwrZrzjP0zIia9+Xmv+DdaTCNUj9UdyT5UAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREEvS3ljdHpsZXJlY3lKVkprbmhaWWxJVTFvMUwyRVFhTW5kR2crWXVaM20xUGhKc2FhMzNTb3VkZXVkVnBTdWZVQT09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDFIoc1AQR8OC2l7aXwIBEIA7pAVMPn0bKicv2GF06mdRGqr6IZctNrW869kDcgeqXsC/IhAiyA3brWRtHO8lDcCx6TOui4cUBl5LbRkCAAAAAVgQnJX1I3I/gwqHN9WBR+wktovleZA+FcMfZK53PD4HJNlQi+hiddz7BzZ2x8dz1Q==',
        'decrypted-dek': 'ApPHw6yUnnWea70HYU9vvgxIiWuk7gMb7lMXR21W8Kk=',
        'encryption-context': {
          'aws-crypto-public-key':
            'A/KyctzlerecyJVJknhZYlIU1o1L2EQaMndGg+YuZ3m1PhJsaa33SoudeudVpSufUA==',
        },
        exception: null,
        'plaintext-frames': [
          '3',
          '3',
          '.',
          ' ',
          '[',
          'C',
          ' ',
          'E',
          'S',
          'D',
          'K',
          ']',
          ' ',
          'a',
          'l',
          'g',
          '=',
          'A',
          'L',
          'G',
          '_',
          'A',
          'E',
          'S',
          '2',
          '5',
          '6',
          '_',
          'G',
          'C',
          'M',
          '_',
          'H',
          'K',
          'D',
          'F',
          '_',
          'S',
          'H',
          'A',
          '5',
          '1',
          '2',
          '_',
          'C',
          'O',
          'M',
          'M',
          'I',
          'T',
          '_',
          'K',
          'E',
          'Y',
          '_',
          'E',
          'C',
          'D',
          'S',
          'A',
          '_',
          'P',
          '3',
          '8',
          '4',
          ';',
          ' ',
          'f',
          'r',
          'a',
          'm',
          'e',
          '_',
          's',
          'i',
          'z',
          'e',
          '=',
          '1',
        ],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '33. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=1',
      },
      {
        ciphertext:
          'AgV4Cri6kFSyB84mx+wt4qgx2ExzbBbVhfDaCweFtJmyyawAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF5N09CbzhYUW9lc0treU1WZHJiZi9TQ3F5MDNtdjU2Y3hkS1ZOa2JoRUU2VWpGYng0VzUzZGkrRytsRTVSMjdOdz09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDM5cn+Y/7Y9bQ29WGwIBEIA7TG4kG9yQfLtTTbvL/NkE9PWXfFT12F9/0zlKLgcHn3ba1Jv8LE7kd5bGR4WZBj4/yZ6QOVOlZKdhU8ECAAAAEOFIohyrSsm7hQfZ7DbWFJhEn6uZoCO7Q0VBqGMiH//ROcwUJFQI0V1re2sMD2gKXwAAAAEAAAAAAAAAAAAAAAHDBPMQUYEwG2fKOjLSy5TzIsJuX6yGSneyX7N8twkLgAAAAAIAAAAAAAAAAAAAAALHIwp6ifqKY4ST4ht1YPK3tMgVKbMA2MGnxO/KASWUZQAAAAMAAAAAAAAAAAAAAAPe7atR4Zuw7rws2Lq3LNDx9HQLgtbxXg2Uop5GGCrMYAAAAAQAAAAAAAAAAAAAAATvARGcM3tkX8Rfw+Z2OG+66JDtoVCeTwwrIKZ0SBYd1gAAAAUAAAAAAAAAAAAAAAXz16pY+9hY6+4aSLMNcMp1uNrLUsSOlZzOqpK+Fugsnv////8AAAAGAAAAAAAAAAAAAAAGAAAAAEpDJdbidG3or3xz3g+j9a0AZzBlAjEA9LQRM/AjRx+cYDuMo0NnK9ZmAaWboUmeRJqQjdaOTLtdaZfn2hDBV6gBsQIaQ2jbAjBP+cYTlMcb2dguFKM0DJRr9bQGcoAp45aIm1IgSSt8/4zvBHAuE38TYu5FFgpnbd0=',
        commitment: '4UiiHKtKybuFB9nsNtYUmESfq5mgI7tDRUGoYyIf/9E=',
        'message-id': 'Cri6kFSyB84mx+wt4qgx2ExzbBbVhfDaCweFtJmyyaw=',
        header:
          'AgV4Cri6kFSyB84mx+wt4qgx2ExzbBbVhfDaCweFtJmyyawAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF5N09CbzhYUW9lc0treU1WZHJiZi9TQ3F5MDNtdjU2Y3hkS1ZOa2JoRUU2VWpGYng0VzUzZGkrRytsRTVSMjdOdz09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDM5cn+Y/7Y9bQ29WGwIBEIA7TG4kG9yQfLtTTbvL/NkE9PWXfFT12F9/0zlKLgcHn3ba1Jv8LE7kd5bGR4WZBj4/yZ6QOVOlZKdhU8ECAAAAEOFIohyrSsm7hQfZ7DbWFJhEn6uZoCO7Q0VBqGMiH//ROcwUJFQI0V1re2sMD2gKXw==',
        'decrypted-dek': 'VJP9B8uCnNxrdEtV8kPaU5pjiK7xL/CgTkLycy1kU+U=',
        'encryption-context': {
          'aws-crypto-public-key':
            'Ay7OBo8XQoesKkyMVdrbf/SCqy03mv56cxdKVNkbhEE6UjFbx4W53di+G+lE5R27Nw==',
        },
        exception: null,
        'plaintext-frames': [
          '34. [C ESDK] alg',
          '=ALG_AES256_GCM_',
          'HKDF_SHA512_COMM',
          'IT_KEY_ECDSA_P38',
          '4; frame_size=16',
        ],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '34. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=16',
      },
      {
        ciphertext:
          'AgV4vg62vd1Hv5VE+VGjBa7oc3FPvQTDk7ZguY9GiKGulTkAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFrR0hBdmFSNVB2bWxRbnQzWXpZQWRKWFlrTUdBMmZLNjJzU1VwSC9jbzd0elM1ZTdXekFuZzNhTlVQU3dLSk15dz09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDMpcqA4MbfdI8aAUOgIBEIA7R9FnrsMXuhPlFikOTW3aKzvEOVWNQPtpeOCLfU+aZhGKhSmkCYomwyogxt3FX3nrjfC3T9qCgCR7Z+UCAAAEAIhjUi358MWbu7FHlNnUMi9LI+65mze4uaZKVo24z2vFwi6+JWRjsiDczse9YIuKCP////8AAAABAAAAAAAAAAAAAAABAAAAUtmGBbD+Xwh+szMmNcT+da9ik8xoO5QTFdDp2SrPulgAb1GaXcbrSCH/3wGjFqbcP0X8x2t9mwuZk7LL+bRme5aYdgy8KsTH4QoYQEVaiVGdV54L2jkURaCut8W4puj0S/qAAGcwZQIwb9jj+9a4kwMeg2TIaBnDlFsRFNz4pru5AkTjm785jJRzxqmNo+8/AxyHjdLpPL3uAjEAnyBFU1XaaHI7+iRblm/9FdbdgvxcvN4aqhjvujvZTbZncE9IMALJviNMHxV9wa0g',
        commitment: 'iGNSLfnwxZu7sUeU2dQyL0sj7rmbN7i5pkpWjbjPa8U=',
        'message-id': 'vg62vd1Hv5VE+VGjBa7oc3FPvQTDk7ZguY9GiKGulTk=',
        header:
          'AgV4vg62vd1Hv5VE+VGjBa7oc3FPvQTDk7ZguY9GiKGulTkAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFrR0hBdmFSNVB2bWxRbnQzWXpZQWRKWFlrTUdBMmZLNjJzU1VwSC9jbzd0elM1ZTdXekFuZzNhTlVQU3dLSk15dz09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDMpcqA4MbfdI8aAUOgIBEIA7R9FnrsMXuhPlFikOTW3aKzvEOVWNQPtpeOCLfU+aZhGKhSmkCYomwyogxt3FX3nrjfC3T9qCgCR7Z+UCAAAEAIhjUi358MWbu7FHlNnUMi9LI+65mze4uaZKVo24z2vFwi6+JWRjsiDczse9YIuKCA==',
        'decrypted-dek': 'B83FiL96eWtjx7o/RNhfeJfHS5n0cGIaPNZjS52TV1w=',
        'encryption-context': {
          'aws-crypto-public-key':
            'AkGHAvaR5PvmlQnt3YzYAdJXYkMGA2fK62sSUpH/co7tzS5e7WzAng3aNUPSwKJMyw==',
        },
        exception: null,
        'plaintext-frames': [
          '35. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=1024',
        ],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '35. [C ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=1024',
      },
      {
        ciphertext:
          'AgR4yNblPxh8dEafsUL5bpyJNqiqn8p+y/7AXcHUbywUVpwAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxa70VQY6/+Av/OLD8CARCAO/v5YAqSmoWIuYyYXF1mrgXuRMSCIan5ihnGlBfWLeayEd35vc+XCXUPkFhkq518ngB09ul3bHPgvphgAgAACAAZ8+mwxDWarFDhqjHmpnIy2q2R80WwF9lAWy4ZCmei64JGBkBhGG4U4vF+Qh4TOMb/////AAAAAQAAAAAAAAAAAAAAAQAAAAmoJ2RCTnS8yT+k0RTr16lJzJ/ISzKB1paB',
        commitment: 'GfPpsMQ1mqxQ4aox5qZyMtqtkfNFsBfZQFsuGQpnous=',
        'message-id': 'yNblPxh8dEafsUL5bpyJNqiqn8p+y/7AXcHUbywUVpw=',
        header:
          'AgR4yNblPxh8dEafsUL5bpyJNqiqn8p+y/7AXcHUbywUVpwAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxa70VQY6/+Av/OLD8CARCAO/v5YAqSmoWIuYyYXF1mrgXuRMSCIan5ihnGlBfWLeayEd35vc+XCXUPkFhkq518ngB09ul3bHPgvphgAgAACAAZ8+mwxDWarFDhqjHmpnIy2q2R80WwF9lAWy4ZCmei64JGBkBhGG4U4vF+Qh4TOMY=',
        'decrypted-dek': 'vfPpEnCooy3XFzxt/4vPIZ2i7ec07PiYmasAU0PT7JY=',
        'encryption-context': {},
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '36. [Python ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY; frame_size=2048',
      },
      {
        ciphertext:
          'AgV47ifhy2pEjH4uPOG+7E9js5isde/lfQ99SPOJ6k44gtMAfwADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFqZGJtM2lxSXFPQWQyT3QzQjZuWGpTYVN2aWZrTmtDMzNpUEpJMjZYNEo0KzRBRGJ4VnFRTndOcjljOFgzcUZOZz09AAVrZXlfYQAHdmFsdWVfYQAFa2V5X2IAB3ZhbHVlX2IAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM8OlFmmVp8XwQLrSrAgEQgDsFOqtWv5PZxNNeWRRGiaTgSHUr69mvDLohdL88CEkTaiAExVWhByMUSpvbbJW9TUmNJWkCd3nhGl90SQIAAAgA+9+06T874sHO44BxZyxznHnDFdH9j1qoZ/XIjE1IZeBnGjkqNF7n262O13osDfHh/////wAAAAEAAAAAAAAAAAAAAAEAAAAJ7Vzzk9nJuGI6j4rF7n3eLTTMWmU0rH25jABnMGUCMQDiZmYTwm7emvFwByAYHYXJQUYfc5FfSpjUp7nNQz9gCboKc3O8z0E/+832YqPQLj8CMA5LI5IofS9NBy5j4GpNpu7CWqUZHDWAEXDjGydjpCBL5Rw9IrrjuIJ81S48w/cY1Q==',
        commitment: '+9+06T874sHO44BxZyxznHnDFdH9j1qoZ/XIjE1IZeA=',
        'message-id': '7ifhy2pEjH4uPOG+7E9js5isde/lfQ99SPOJ6k44gtM=',
        header:
          'AgV47ifhy2pEjH4uPOG+7E9js5isde/lfQ99SPOJ6k44gtMAfwADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFqZGJtM2lxSXFPQWQyT3QzQjZuWGpTYVN2aWZrTmtDMzNpUEpJMjZYNEo0KzRBRGJ4VnFRTndOcjljOFgzcUZOZz09AAVrZXlfYQAHdmFsdWVfYQAFa2V5X2IAB3ZhbHVlX2IAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM8OlFmmVp8XwQLrSrAgEQgDsFOqtWv5PZxNNeWRRGiaTgSHUr69mvDLohdL88CEkTaiAExVWhByMUSpvbbJW9TUmNJWkCd3nhGl90SQIAAAgA+9+06T874sHO44BxZyxznHnDFdH9j1qoZ/XIjE1IZeBnGjkqNF7n262O13osDfHh',
        'decrypted-dek': '27Mr50n9EYgz/iYs6a1xpgQJaw0u4bPtxI2gUE08Dkg=',
        'encryption-context': {
          key_a: 'value_a',
          key_b: 'value_b',
          'aws-crypto-public-key':
            'Ajdbm3iqIqOAd2Ot3B6nXjSaSvifkNkC33iPJI26X4J4+4ADbxVqQNwNr9c8X3qFNg==',
        },
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '37. [Python ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frame_size=2048',
      },
      {
        ciphertext:
          'AgV4wjhFuoHhF6np5UvxBujGNCGe8CcoCsePw7aXzeLgH8wAfwADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREE4dXY0S0lYWlIwTWhwUm5kQ3ZZK0p1elRRcStqVWxacnBWMHM5RXFNV0ZjaFRBd0FIVXdIK2tOSzA5S3BBQnkwdz09AAVrZXlfYQAHdmFsdWVfYQAFa2V5X2IAB3ZhbHVlX2IAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMvsueY9q2K9SdGKfuAgEQgDvLQ5OljOCV1/YH/tYzl8WF+LGPRRj07YoY41t9XjjzZkhjH6nhZfY+QO8CLSM8ut1UDcjsiHMc8wAPPQEAAAAArqoSW/LCsWqA2PzItFUJsyDF/wAPCbMzc6YuAdKnWXvUPTIdnPA3H7jAmRegjNLnAAAAAAAAAAAAAAABAAAAAAAAAAkdnEdnIYuM46iNVFb59YSGI28tcMvNOTHdAGcwZQIxAItH5NgTud0q8MNvhktGLyG2UDTJHxiDJ5yZs5Tuc9Vlxl/t2cGFdJqp1vopF4RxhAIwToqh7JWjG24wQ3t9mXSLpoNwJL2WotrznE/XIcjW4SZLtjETsQGq+yF92XR6s8Ur',
        commitment: 'rqoSW/LCsWqA2PzItFUJsyDF/wAPCbMzc6YuAdKnWXs=',
        'message-id': 'wjhFuoHhF6np5UvxBujGNCGe8CcoCsePw7aXzeLgH8w=',
        header:
          'AgV4wjhFuoHhF6np5UvxBujGNCGe8CcoCsePw7aXzeLgH8wAfwADABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREE4dXY0S0lYWlIwTWhwUm5kQ3ZZK0p1elRRcStqVWxacnBWMHM5RXFNV0ZjaFRBd0FIVXdIK2tOSzA5S3BBQnkwdz09AAVrZXlfYQAHdmFsdWVfYQAFa2V5X2IAB3ZhbHVlX2IAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtd2VzdC0yOjY1ODk1NjYwMDgzMzprZXkvYjM1MzdlZjEtZDhkYy00NzgwLTlmNWEtNTU3NzZjYmIyZjdmAKcBAQEAeEDzjCdeMQl0FsEHKVFQVxlkraPvHCHpTIugvbydD7QUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMvsueY9q2K9SdGKfuAgEQgDvLQ5OljOCV1/YH/tYzl8WF+LGPRRj07YoY41t9XjjzZkhjH6nhZfY+QO8CLSM8ut1UDcjsiHMc8wAPPQEAAAAArqoSW/LCsWqA2PzItFUJsyDF/wAPCbMzc6YuAdKnWXvUPTIdnPA3H7jAmRegjNLn',
        'decrypted-dek': 'qApow0AClB0e1zK5u4NLs33LpEbugfQgH5JTYXn2MvY=',
        'encryption-context': {
          key_a: 'value_a',
          key_b: 'value_b',
          'aws-crypto-public-key':
            'A8uv4KIXZR0MhpRndCvY+JuzTQq+jUlZrpV0s9EqMWFchTAwAHUwH+kNK09KpABy0w==',
        },
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '38. [Python ESDK] alg=ALG_AES256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed',
      },
      {
        ciphertext:
          'AgR4SKFdV3T67xu9VbyFL2tA8QdxcqAxzgD7Eh13p8M5cMcAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxln6D0fSs0n3QylqECARCAO49ROJ2rH9g3yzoyD2O3CqMCM+vYYYf9LdgxgWSpic1pBiox441RgiXNTen/xE8KH5KFApq7UxF6cVmUAgAACAAVpe6A8Ntdm2I23PgG9j0YsKxz+5AzUVADJtE5fhaQktSunzx3GUVkkZNV9X66ONn/////AAAAAQAAAAAAAAAAAAAAAQAAAAnLTOSn7ir+xUizlogMTuv032ic0uHdwvS+',
        commitment: 'FaXugPDbXZtiNtz4BvY9GLCsc/uQM1FQAybROX4WkJI=',
        'message-id': 'SKFdV3T67xu9VbyFL2tA8QdxcqAxzgD7Eh13p8M5cMc=',
        header:
          'AgR4SKFdV3T67xu9VbyFL2tA8QdxcqAxzgD7Eh13p8M5cMcAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxln6D0fSs0n3QylqECARCAO49ROJ2rH9g3yzoyD2O3CqMCM+vYYYf9LdgxgWSpic1pBiox441RgiXNTen/xE8KH5KFApq7UxF6cVmUAgAACAAVpe6A8Ntdm2I23PgG9j0YsKxz+5AzUVADJtE5fhaQktSunzx3GUVkkZNV9X66ONk=',
        'decrypted-dek': 'bg8qt1PWj3LyfQbmltjoZyFAm/Pgs0Ft8YvOwhzEO78=',
        'encryption-context': {},
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '39. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY; frameSize=2048',
      },
      {
        ciphertext:
          'AgR489rpKG1gc7jEIpNVoPmEidpm/S6/mMNmpo5DUPtjfvoAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwj+RmdJoCGvYKswYkCARCAO4v0/pYT9NN+9UN1a+Wwt4ME2TQUXCGDLktXwOPTrpzzKbsdey847gJLMscis/PnhJFjIInSl7YXTs4sAQAAAAD4mNRyy2Ilyp28lKHdEvDtfZG56XuJjZUp1tPYfAy0EmkB6jixZ5UADkWCIjCQLYkAAAAAAAAAAAAAAAEAAAAAAAAACaZigN09HSXKB3hv/nlrI7juPtl66ZV0Pz8=',
        commitment: '+JjUcstiJcqdvJSh3RLw7X2Ruel7iY2VKdbT2HwMtBI=',
        'message-id': '89rpKG1gc7jEIpNVoPmEidpm/S6/mMNmpo5DUPtjfvo=',
        header:
          'AgR489rpKG1gc7jEIpNVoPmEidpm/S6/mMNmpo5DUPtjfvoAAAABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwj+RmdJoCGvYKswYkCARCAO4v0/pYT9NN+9UN1a+Wwt4ME2TQUXCGDLktXwOPTrpzzKbsdey847gJLMscis/PnhJFjIInSl7YXTs4sAQAAAAD4mNRyy2Ilyp28lKHdEvDtfZG56XuJjZUp1tPYfAy0EmkB6jixZ5UADkWCIjCQLYk=',
        'decrypted-dek': 'jUopPfY/IoBzCxwLOuIAMcPIgV8CqHbET1rRxbVLYZc=',
        'encryption-context': {},
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '40. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY; unframed',
      },
      {
        ciphertext:
          'AgR4vafj1mv/vUetSfKzMMMdBBhex4G16PjlJ8K+9OByS6IAHgACAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyI8tQDiO0m7qOfNg0CARCAO+VgyLtxT+Eb02elXBaCQ3cz55+SvPcqHHUXXuCX8JaWXgq0InC8zDfr6KfTc1itDb86rBsOLEoyAPT9AgAACAASKDlK/F3PcVnpZ/IV03tWNmt60wMWMIxI40arC9KXaLV0vuEnPh6RTqoptrrWITT/////AAAAAQAAAAAAAAAAAAAAAQAAAAkCrP0akjzj2aPe8qr9NwhMueXE1c27YMph',
        commitment: 'Eig5Svxdz3FZ6WfyFdN7VjZretMDFjCMSONGqwvSl2g=',
        'message-id': 'vafj1mv/vUetSfKzMMMdBBhex4G16PjlJ8K+9OByS6I=',
        header:
          'AgR4vafj1mv/vUetSfKzMMMdBBhex4G16PjlJ8K+9OByS6IAHgACAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAyI8tQDiO0m7qOfNg0CARCAO+VgyLtxT+Eb02elXBaCQ3cz55+SvPcqHHUXXuCX8JaWXgq0InC8zDfr6KfTc1itDb86rBsOLEoyAPT9AgAACAASKDlK/F3PcVnpZ/IV03tWNmt60wMWMIxI40arC9KXaLV0vuEnPh6RTqoptrrWITQ=',
        'decrypted-dek': 'MZv4plYYs6q9TOExQ5P+HeH3NOKIRXjiLVv2Vj8LSxQ=',
        'encryption-context': {
          KeyB: 'ValueB',
          KeyA: 'ValueA',
        },
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '41. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY; frameSize=2048',
      },
      {
        ciphertext:
          'AgR4bhUk0J5Af3Nq/UkQD6Dqx3ru9xUluYP6CW+318aF9hUAHgACAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAw6iQ92YNQm0DM9RKACARCAO/86abwJHCx3jzUuMGFStBVCKwXla3beFh0tsco5I9yuNKahzl60HDzG08n3szNFsCFgSg39Mg47ABiXAQAAAADoJEHTCZXi5+RjdcDY/SDrBc4gcsZIJ7SjSj1D3hsUf6rJ1u+UKD8iaMm0Ae6gVX0AAAAAAAAAAAAAAAEAAAAAAAAACQaK024+LpXF6tV/ekHQSmrC4ZABZTZqUJY=',
        commitment: '6CRB0wmV4ufkY3XA2P0g6wXOIHLGSCe0o0o9Q94bFH8=',
        'message-id': 'bhUk0J5Af3Nq/UkQD6Dqx3ru9xUluYP6CW+318aF9hU=',
        header:
          'AgR4bhUk0J5Af3Nq/UkQD6Dqx3ru9xUluYP6CW+318aF9hUAHgACAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAw6iQ92YNQm0DM9RKACARCAO/86abwJHCx3jzUuMGFStBVCKwXla3beFh0tsco5I9yuNKahzl60HDzG08n3szNFsCFgSg39Mg47ABiXAQAAAADoJEHTCZXi5+RjdcDY/SDrBc4gcsZIJ7SjSj1D3hsUf6rJ1u+UKD8iaMm0Ae6gVX0=',
        'decrypted-dek': '67b7K61ls7BZ76vRXY1Ydl13KvFEtF44Lb8V1A+qaWk=',
        'encryption-context': {
          KeyB: 'ValueB',
          KeyA: 'ValueA',
        },
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '42. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY; unframed',
      },
      {
        ciphertext:
          'AgV4kRpnmOGf7OG3OqrPlL6SqR4ZO7nvoOOfkB/NOmJ9VJUAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFtN1Z3eG12OGhoc0kxL2VEUThMTzVna2dyTGw5Y3MvZE5QWWRsL1laMkxjamxCdldxRzVwb2FWaytLM0psejFBUT09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDOj+C2KslbEZcT2PSgIBEIA7K6QwakePtQ0xW+Ip/0cNi7DkMqwTGORmv5asamzXbUKz28JNCInaqW14aIuuwwsm0z3+809CE+ko72MCAAAIAG4FL0GhcP4Vc8AUVzjbvzYhLikm6htqY5pQtOEbLI8vwrg/XVgcMv7hpEMsgmnr1v////8AAAABAAAAAAAAAAAAAAABAAAACWk9CHIOP9+CMH6UJi1wsxwKA2UiLbPKa0oAZzBlAjBN+Qychto+YKgiEJUtrFuWjEs7M+V8UCim4+pN9FtZmiEgchHyQnMSCyvV95kHtFsCMQDs0M1Bjg3s2bfLKsiH+hkJePl+Hasn8bNwPShA54u1eXCnm1mv8+yjNLy19DDXSl4=',
        commitment: 'bgUvQaFw/hVzwBRXONu/NiEuKSbqG2pjmlC04Rssjy8=',
        'message-id': 'kRpnmOGf7OG3OqrPlL6SqR4ZO7nvoOOfkB/NOmJ9VJU=',
        header:
          'AgV4kRpnmOGf7OG3OqrPlL6SqR4ZO7nvoOOfkB/NOmJ9VJUAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREFtN1Z3eG12OGhoc0kxL2VEUThMTzVna2dyTGw5Y3MvZE5QWWRsL1laMkxjamxCdldxRzVwb2FWaytLM0psejFBUT09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDOj+C2KslbEZcT2PSgIBEIA7K6QwakePtQ0xW+Ip/0cNi7DkMqwTGORmv5asamzXbUKz28JNCInaqW14aIuuwwsm0z3+809CE+ko72MCAAAIAG4FL0GhcP4Vc8AUVzjbvzYhLikm6htqY5pQtOEbLI8vwrg/XVgcMv7hpEMsgmnr1g==',
        'decrypted-dek': 'N1FQDxFaNrglCmz/yTTVfZVh36k3KvgeKpZuHrvdCbg=',
        'encryption-context': {
          'aws-crypto-public-key':
            'Am7Vwxmv8hhsI1/eDQ8LO5gkgrLl9cs/dNPYdl/YZ2LcjlBvWqG5poaVk+K3Jlz1AQ==',
        },
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '43. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frameSize=2048',
      },
      {
        ciphertext:
          'AgV48AP2Janq1bcZ1DrZJtaJNM24UZD9UX7R2/yP+4OzLuMAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF4UWphQ1NXQzkzSWJZV3ZLbFhNUWlybFEyZVBBeUlRcUJ6am1zK1NtZVo4d0txazJyS1lPVHJMOFFqWVVzMVR3Zz09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDDD5mSvuYzwT9/eJ9QIBEIA7vnyXsGXnLURceBmqLlK8soxg/cIstDKW1XCI0OfGY4yhYjjr0l9XwAu0clOYrJdpwJNjYAz8uIpnXs0BAAAAANDc3n2TAsoULoixfm5jipiQ2qABoB2KBteVpJ1xvjgRidbCTV7O5ggCOjqfRt8YcgAAAAAAAAAAAAAAAQAAAAAAAAAJ7o9NINW0Q1jdL6PfMKn+f6izn2bU5QJOcQBnMGUCMBF6eRMvcIRQ+7kb/dxKaFem2GFa0vnpoBclaik6SWH1/J+qSyIwskpIG8yrWvkjDwIxAOSeqMPZX2uZbbExbyWZUE1/rC1f4JqA0wFTkWPTEIkfu9YCo2ZhdZrVm1xeqjmr0g==',
        commitment: '0NzefZMCyhQuiLF+bmOKmJDaoAGgHYoG15WknXG+OBE=',
        'message-id': '8AP2Janq1bcZ1DrZJtaJNM24UZD9UX7R2/yP+4OzLuM=',
        header:
          'AgV48AP2Janq1bcZ1DrZJtaJNM24UZD9UX7R2/yP+4OzLuMAXwABABVhd3MtY3J5cHRvLXB1YmxpYy1rZXkAREF4UWphQ1NXQzkzSWJZV3ZLbFhNUWlybFEyZVBBeUlRcUJ6am1zK1NtZVo4d0txazJyS1lPVHJMOFFqWVVzMVR3Zz09AAEAB2F3cy1rbXMAS2Fybjphd3M6a21zOnVzLXdlc3QtMjo2NTg5NTY2MDA4MzM6a2V5L2IzNTM3ZWYxLWQ4ZGMtNDc4MC05ZjVhLTU1Nzc2Y2JiMmY3ZgCnAQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDDD5mSvuYzwT9/eJ9QIBEIA7vnyXsGXnLURceBmqLlK8soxg/cIstDKW1XCI0OfGY4yhYjjr0l9XwAu0clOYrJdpwJNjYAz8uIpnXs0BAAAAANDc3n2TAsoULoixfm5jipiQ2qABoB2KBteVpJ1xvjgRidbCTV7O5ggCOjqfRt8Ycg==',
        'decrypted-dek': 'xhOuDy6HPNHtVzACWDor5m2KyT69vFGsv3wRP0OMJG0=',
        'encryption-context': {
          'aws-crypto-public-key':
            'AxQjaCSWC93IbYWvKlXMQirlQ2ePAyIQqBzjms+SmeZ8wKqk2rKYOTrL8QjYUs1Twg==',
        },
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '44. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed',
      },
      {
        ciphertext:
          'AgV4wPGtUdkHghbL8J2/2JO48DSSazj5Z2HLrY1NsW0XKnUAewADAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgAVYXdzLWNyeXB0by1wdWJsaWMta2V5AERBMnJLdFI0Q082NWtiWEttaVlQY3VXZEk0aXJ2OUJZWGV5RXJzdFp6VzU1eDZNOGFBZTJSR1hnZjF5Q1Y2cmZiZGc9PQABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxM5zuF0GHdLiOWtw0CARCAOyep7YpLEJtixgbgjRDDP15ffP7C9Sma9PC1T55rcDTBKiArCbu4zH849ZPSzc+zeeHcSDc1LZOtCFUGAgAACADpb8LgUoW6cWWE7VLLY1Yp/w3r9hw02ZPVxxXc4WrPwp6oUhEnIzWOoXWnOF+KX5//////AAAAAQAAAAAAAAAAAAAAAQAAAAnFSX0svHUHX5oYM5mZeQH+lI/B9cYxRX2EAGcwZQIwTWCrBLIkRLWjWpKmdbpKSexC4w7UJlR0SMud5kym5+Hs9+VFho3PblnEQ5qXtS5RAjEApDNPjapvgGdC5t+ti8L6NFjFhrsc1fROpUiNno2A86+QjLUQe0BuRoPmHlPWl0ez',
        commitment: '6W/C4FKFunFlhO1Sy2NWKf8N6/YcNNmT1ccV3OFqz8I=',
        'message-id': 'wPGtUdkHghbL8J2/2JO48DSSazj5Z2HLrY1NsW0XKnU=',
        header:
          'AgV4wPGtUdkHghbL8J2/2JO48DSSazj5Z2HLrY1NsW0XKnUAewADAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgAVYXdzLWNyeXB0by1wdWJsaWMta2V5AERBMnJLdFI0Q082NWtiWEttaVlQY3VXZEk0aXJ2OUJZWGV5RXJzdFp6VzU1eDZNOGFBZTJSR1hnZjF5Q1Y2cmZiZGc9PQABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxM5zuF0GHdLiOWtw0CARCAOyep7YpLEJtixgbgjRDDP15ffP7C9Sma9PC1T55rcDTBKiArCbu4zH849ZPSzc+zeeHcSDc1LZOtCFUGAgAACADpb8LgUoW6cWWE7VLLY1Yp/w3r9hw02ZPVxxXc4WrPwp6oUhEnIzWOoXWnOF+KX58=',
        'decrypted-dek': 'vxGKyd1THdpAdVHmYdoLwsY7Vw9C6pGQLhdVwarE0Lw=',
        'encryption-context': {
          KeyB: 'ValueB',
          KeyA: 'ValueA',
          'aws-crypto-public-key':
            'A2rKtR4CO65kbXKmiYPcuWdI4irv9BYXeyErstZzW55x6M8aAe2RGXgf1yCV6rfbdg==',
        },
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '45. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; frameSize=2048',
      },
      {
        ciphertext:
          'AgV4NIrbgvJHnrCNOqOP2FRfO9GITBLJd8xbEvhJu3WNCUAAewADAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgAVYXdzLWNyeXB0by1wdWJsaWMta2V5AERBd1NZQ21RODYybmVKRUlBRU9YczRqVGIzVlBLL1pwbWtOSkR6eGFRaVVjR0VTUGxZekd1K3cxQkt2cjhIOWlYemc9PQABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwcMP008tCOAHWwKMQCARCAO6JddAzG8rjYhkiifNg+u9CV3YrfgX3/WJLQVfruPM8rAY6b0h1CA59q9287F3wAz4TdBDvOJx25OjL0AQAAAAB/DPmV33Jz8DtfV/0gBSp21AE5JTdylNEwTsUcnHyofXYjPvkvq6aJCt3gWOLtnSkAAAAAAAAAAAAAAAEAAAAAAAAACaX0vpCBWsCd0SKJWqWLPmqKgG2g961qBIoAZzBlAjEAo3oAliRCOvhExMFaAtgdHJhguUdlEKE8HYGEbCWILUcmY3pdQEZWF9av1eMGOT5uAjBeKCuCrzI496vqYC3eChefw4J7bGrWTcUZVwCbijJV/VehvV8WoH1kds8esTZl24Y=',
        commitment: 'fwz5ld9yc/A7X1f9IAUqdtQBOSU3cpTRME7FHJx8qH0=',
        'message-id': 'NIrbgvJHnrCNOqOP2FRfO9GITBLJd8xbEvhJu3WNCUA=',
        header:
          'AgV4NIrbgvJHnrCNOqOP2FRfO9GITBLJd8xbEvhJu3WNCUAAewADAARLZXlBAAZWYWx1ZUEABEtleUIABlZhbHVlQgAVYXdzLWNyeXB0by1wdWJsaWMta2V5AERBd1NZQ21RODYybmVKRUlBRU9YczRqVGIzVlBLL1pwbWtOSkR6eGFRaVVjR0VTUGxZekd1K3cxQkt2cjhIOWlYemc9PQABAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NjU4OTU2NjAwODMzOmtleS9iMzUzN2VmMS1kOGRjLTQ3ODAtOWY1YS01NTc3NmNiYjJmN2YApwEBAQB4QPOMJ14xCXQWwQcpUVBXGWSto+8cIelMi6C9vJ0PtBQAAAB+MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwcMP008tCOAHWwKMQCARCAO6JddAzG8rjYhkiifNg+u9CV3YrfgX3/WJLQVfruPM8rAY6b0h1CA59q9287F3wAz4TdBDvOJx25OjL0AQAAAAB/DPmV33Jz8DtfV/0gBSp21AE5JTdylNEwTsUcnHyofXYjPvkvq6aJCt3gWOLtnSk=',
        'decrypted-dek': 'k/f3Ora/LfrKWi/gAkrVUJy7BTVeotHdFR4fTPk2Lc8=',
        'encryption-context': {
          KeyB: 'ValueB',
          KeyA: 'ValueA',
          'aws-crypto-public-key':
            'AwSYCmQ862neJEIAEOXs4jTb3VPK/ZpmkNJDzxaQiUcGESPlYzGu+w1BKvr8H9iXzg==',
        },
        exception: null,
        'plaintext-frames': ['testing12'],
        status: true,
        'keyring-type': 'aws-kms',
        comment:
          '46. [Java ESDK] alg=ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384; unframed',
      },
    ],
  }
}
