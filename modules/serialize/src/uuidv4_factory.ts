// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { needs } from '@aws-crypto/material-management'
import { validate, version } from 'uuid'

// function to validate a string as uuidv4
const validateUuidv4 = (input: string): boolean =>
  validate(input) && version(input) === 4

// accepts user defined lambda functions to convert between a string and
// compressed hex encoded
// bytes. This factory is a higher order function that returns the compression
// and decompression functions based on the input lambda functions
export function uuidv4Factory(
  stringToHexBytes: (input: string) => Uint8Array,
  hexBytesToString: (input: Uint8Array) => string
) {
  return { uuidv4ToCompressedBytes, decompressBytesToUuidv4 }

  // remove the '-' chars from the uuid string and convert to hex bytes
  function uuidv4ToCompressedBytes(uuidString: string): Uint8Array {
    /* Precondition: Input string must be valid uuidv4 */
    needs(validateUuidv4(uuidString), 'Input must be valid uuidv4')

    const uuidBytes = new Uint8Array(
      stringToHexBytes(uuidString.replace(/-/g, ''))
    )

    /* Postcondition: Compressed bytes must have correct byte length */
    needs(
      uuidBytes.length === 16,
      'Unable to convert uuid into compressed bytes'
    )

    return uuidBytes
  }

  // convert the hex bytes to a string. Reconstruct the uuidv4 string with the
  // '-' chars
  function decompressBytesToUuidv4(uuidBytes: Uint8Array): string {
    /* Precondition: Compressed bytes must have correct byte length */
    needs(uuidBytes.length === 16, 'Compressed uuid has incorrect byte length')

    const hex = hexBytesToString(uuidBytes)
    let uuidString: string

    try {
      // These represent the ranges of the uuidv4 string that contain
      // alphanumeric chars. We want to rebuild the proper uuidv4 string by
      // joining these segments with the '-' char
      uuidString = [
        hex.slice(0, 8),
        hex.slice(8, 12),
        hex.slice(12, 16),
        hex.slice(16, 20),
        hex.slice(20),
      ].join('-')
    } catch {
      throw new Error('Unable to decompress UUID compressed bytes')
    }

    /* Postcondition: Output string must be valid uuidv4  */
    needs(validateUuidv4(uuidString), 'Input must represent a uuidv4')

    return uuidString
  }
}
