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

export enum SerializationVersion {
  V1 = 1 // eslint-disable-line no-unused-vars
}
Object.freeze(SerializationVersion)

export enum ContentType {
  NO_FRAMING = 1, // eslint-disable-line no-unused-vars
  FRAMED_DATA = 2 // eslint-disable-line no-unused-vars
}
Object.freeze(ContentType)

export enum ContentAADString {
  FRAME_STRING_ID = 'AWSKMSEncryptionClient Frame', // eslint-disable-line no-unused-vars
  FINAL_FRAME_STRING_ID = 'AWSKMSEncryptionClient Final Frame', // eslint-disable-line no-unused-vars
  NON_FRAMED_STRING_ID = 'AWSKMSEncryptionClient Single Block', // eslint-disable-line no-unused-vars
}
Object.freeze(ContentAADString)

export enum ObjectType {
  CUSTOMER_AE_DATA = 128 // eslint-disable-line no-unused-vars
}
Object.freeze(ObjectType)

export enum SequenceIdentifier {
  SEQUENCE_NUMBER_END = 0xFFFFFFFF // eslint-disable-line no-unused-vars
}
Object.freeze(SequenceIdentifier)

export enum Maximum {
  // Maximum number of messages which are allowed to be encrypted under a single cached data key
  MESSAGES_PER_KEY = 2 ** 32, // eslint-disable-line no-unused-vars
  /* Maximum number of bytes which are allowed to be encrypted
   * under a cached single data key across messages.
   * The _real_ maximum is 2 ** 63 - 1,
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
   *
   * This is *not* the maximum amount of data that can be encrypted under a single data key
   * or under a single AES operation.
   * The maximum amount of data that can be safely encrypted under a single AES operation is 2 ** 36 -32.
   * However the AWS Encryption SDK for Javascript does not support non-framed encryption.
   * Therefore the largest single AES operation supported
   * by the AWS Encryption SDK for Javascript is the maximum frame size 2 **32 -1.
   * The maximum amount of data that can be encrypted by the AWS Encryption SDK
   * is the maximum number of frames at the maximum frame size.
   * (number of frames) * (frame size) == (2 ** 32 - 1) * (2 ** 32 -1) ~ 2 ** 64 ~ 1.8e19 bytes.
   */
  BYTES_PER_KEY = 2 ** 53 - 1, // eslint-disable-line no-unused-vars
  // Maximum number of frames allowed in one message as defined in specification
  FRAME_COUNT = 2 ** 32 - 1, // eslint-disable-line no-unused-vars
  // Maximum bytes allowed in a single frame as defined in specification
  FRAME_SIZE = 2 ** 32 - 1, // eslint-disable-line no-unused-vars
  // Maximum bytes allowed in a non-framed message ciphertext as defined in specification
  GCM_CONTENT_SIZE = 2 ** 32 - 1, // eslint-disable-line no-unused-vars
  NON_FRAMED_SIZE = 2 ** 32 - 1, // eslint-disable-line no-unused-vars
  // Maximum number of AAD bytes allowed as defined in specification
  AAD_BYTE_SIZE = 2 ** 16 - 1, // eslint-disable-line no-unused-vars
}
Object.freeze(Maximum)

// Default frame length when using framing
export const FRAME_LENGTH = 4096
// Message ID length as defined in specification
export const MESSAGE_ID_LENGTH = 16
