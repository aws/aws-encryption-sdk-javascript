/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

export function basicMessageHeader () {
  return new Uint8Array([ 1, 128, 0, 20, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 43, 0, 2, 0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99, 0, 2, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 8, 102, 105, 114, 115, 116, 75, 101, 121, 0, 5, 1, 2, 3, 4, 5, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 9, 115, 101, 99, 111, 110, 100, 75, 101, 121, 0, 5, 6, 7, 8, 9, 0, 2, 0, 0, 0, 0, 12, 0, 0, 16, 0 ])
}

export function zeroByteEncryptionContextMessageHeader () {
  return new Uint8Array([ 1, 128, 0, 20, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    0, 0, // see here, 0,0 for context length, but _no_ element count
    0, 2, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 8, 102, 105, 114, 115, 116, 75, 101, 121, 0, 5, 1, 2, 3, 4, 5, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 9, 115, 101, 99, 111, 110, 100, 75, 101, 121, 0, 5, 6, 7, 8, 9, 0, 2, 0, 0, 0, 0, 12, 0, 0, 16, 0 ])
}

export function basicFrameHeader () {
  return new Uint8Array([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

export function finalFrameHeader () {
  return new Uint8Array([255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3, 231])
}

export function basicNonFrameHeader () {
  return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])
}

export function basicEncryptionContext () {
  return new Uint8Array([ 0, 43, 0, 2, 0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99 ])
}

export function missingDataEncryptionContext () {
  return new Uint8Array([ 0, 43, 0, 2, 0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108 ])
}

export function tooMuchDataEncryptionContext () {
  return new Uint8Array([ 0, 43, 0, 2, 0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99, 0 ])
}

export function duplicateKeysEncryptionContext () {
  return new Uint8Array([ 0, 43, 0, 4, 0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 11, 105, 110, 102, 111, 114, 109, 97, 116, 105, 111, 110, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99, 0, 4, 115, 111, 109, 101, 0, 6, 112, 117, 98, 108, 105, 99 ])
}

export function basicFrameIV () {
  return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

export function basicNonFrameIV () {
  return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

export function headerAuthIV () {
  return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}

export function encryptedDataKey () {
  return new Uint8Array([ 0, 2, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 8, 102, 105, 114, 115, 116, 75, 101, 121, 0, 5, 1, 2, 3, 4, 5, 0, 12, 194, 189, 32, 43, 32, 194, 188, 32, 61, 32, 194, 190, 0, 9, 115, 101, 99, 111, 110, 100, 75, 101, 121, 0, 5, 6, 7, 8, 9, 0 ])
}
