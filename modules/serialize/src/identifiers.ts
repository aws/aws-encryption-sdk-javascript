// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This public interface for constants is provided for
 * the use of the Encryption SDK for JavaScript only.  It can be used
 * as a reference but is not intended to be use by any packages other
 * than the Encryption SDK for JavaScript.
 *
 * See: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/reference.html
 *
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-aad (algorithms with signing)
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-version
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-content-type
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/body-aad-reference.html (Body AAD Content)
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-type
 * https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/body-aad-reference.html#body-aad-sequence-number
 */

export const ENCODED_SIGNER_KEY = 'aws-crypto-public-key'
/** @deprecated use import { MessageFormat } from '@aws-crypto/material-management' */
export { MessageFormat as SerializationVersion } from '@aws-crypto/material-management'

export enum ContentType {
  NO_FRAMING = 1,
  FRAMED_DATA = 2,
}
Object.freeze(ContentType)

export enum ContentAADString {
  FRAME_STRING_ID = 'AWSKMSEncryptionClient Frame',
  FINAL_FRAME_STRING_ID = 'AWSKMSEncryptionClient Final Frame',
  NON_FRAMED_STRING_ID = 'AWSKMSEncryptionClient Single Block',
}
Object.freeze(ContentAADString)

export enum ObjectType {
  CUSTOMER_AE_DATA = 128,
}
Object.freeze(ObjectType)

export enum SequenceIdentifier {
  SEQUENCE_NUMBER_END = 0xffffffff,
}
Object.freeze(SequenceIdentifier)

export enum Maximum {
  // Maximum number of messages which are allowed to be encrypted under a single cached data key
  MESSAGES_PER_CACHED_KEY_LIMIT = 2 ** 32,
  /* Maximum number of bytes that are allowed to be encrypted
   * under a single cached data key across messages.
   * The maximum value defined in the AWS Encryption SDK specification is 2 ** 63 - 1.
   * However Javascript can only perform safe operations on values
   * up to Number.MAX_SAFE_INTEGER === 9007199254740991 === 2 ** 53 - 1.
   * e.g
   * Number.MAX_SAFE_INTEGER + 1 === Number.MAX_SAFE_INTEGER + 2 => true
   * Number.MAX_SAFE_INTEGER + 1 > Number.MAX_SAFE_INTEGER + 2 => false
   * Number.MAX_SAFE_INTEGER + 1 < Number.MAX_SAFE_INTEGER + 2 => false
   *
   * This means that after 2 ** 53 - 1 the process of accumulating a byte count
   * will never yield an accurate comparison and so, never halt.
   *
   * The choice here to use 2 ** 53 - 1 instead of Number.MAX_SAFE_INTEGER is deliberate.
   * This is because in the future Number.MAX_SAFE_INTEGER could be raised to 2 ** 66
   * or some value larger 2 ** 63.
   */
  BYTES_PER_CACHED_KEY_LIMIT = 2 ** 53 - 1,
  /* This value should be Maximum.FRAME_COUNT * Maximum.FRAME_SIZE.
   * However this would be ~ 2 ** 64, much larger than Number.MAX_SAFE_INTEGER.
   * For the same reasons outlined above in BYTES_PER_CACHED_KEY_LIMIT
   * this value is set to 2 ** 53 - 1.
   */
  BYTES_PER_MESSAGE = 2 ** 53 - 1,
  /* Maximum number of bytes for a single AES-GCM "operation."
   * This is related to the GHASH block size,
   * and can be thought of as the maximum bytes
   * that can be encrypted with a single key/IV pair.
   * The AWS Encryption SDK for Javascript
   * does not support non-framed encrypt
   * https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md#non-framed-data
   * So this value is only needed to ensure
   * that messages submitted for decrypt
   * are well formed.
   */
  BYTES_PER_AES_GCM_NONCE = 2 ** 36 - 32,
  // Maximum number of frames allowed in one message as defined in specification
  FRAME_COUNT = 2 ** 32 - 1,
  // Maximum bytes allowed in a single frame as defined in specification
  FRAME_SIZE = 2 ** 32 - 1,
  // Maximum bytes allowed in a non-framed message ciphertext as defined in specification
  GCM_CONTENT_SIZE = 2 ** 32 - 1,
  NON_FRAMED_SIZE = 2 ** 32 - 1,
  // Maximum number of AAD bytes allowed as defined in specification
  AAD_BYTE_SIZE = 2 ** 16 - 1,
}
Object.freeze(Maximum)

// Default frame length when using framing
export const FRAME_LENGTH = 4096
// Message ID length as defined in specification
export enum MessageIdLength {
  V1 = 16,
  V2 = 32,
}
Object.freeze(MessageIdLength)

/** @deprecated use MessageIdLength */
export const MESSAGE_ID_LENGTH = MessageIdLength.V1
