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
