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

/**
 * When a keyring is called it produces a trace of what actions it took with the
 * different wrapping keys it manages. The trace is a list of these records.
 *
 * The flags argument uses bit flags to indicate which actions were taken.
 *
 * The other arguments are identifiers which indicate which wrapping key was used
 * to do data key encryption by a keyring. Most keyring implementations write
 * the wrapping key namespace into the provider ID field of EDKs and the
 * wrapping key name into the provider info field of EDKs, and all new keyring
 * implementations should follow this practice. For legacy reasons, the raw AES
 * keyring includes other data in the provider ID field, but only the first part
 * of that field corresponds to what is stored in the name field here.
 *
 * Note: "Master Key (MK)" is used as a class name in the Java and Python
 * implementations of the AWS Encryption SDK, where it is an abstraction of a
 * single wrapping key, and "Master Key Provider (MKP)" is a class that provides
 * multiple wrapping keys. In newer implementations of AWS Encryption SDK, the keyring
 * replaces both of these concepts. It handles one or multiple wrapping keys,
 * which makes it similar to an MKP, but from an API perspective it is in some
 * ways closer to an MK. In order to avoid confusion with the MK class of the
 * Java and Python SDKs, we always refer to a single entity used by a keyring
 * for data key encryption as a wrapping key.
 *
 * The motivating example of a wrapping key is a KMS CMK, for which the
 * namespace is "aws-kms" and the name is the key ARN.
 */

export interface KeyringTrace {
  readonly keyNamespace: String
  readonly keyName: String
  flags: KeyringTraceFlag
}

export enum KeyringTraceFlag {
/**
 * Bit flag indicating this wrapping key generated the data key.
 */
  WRAPPING_KEY_GENERATED_DATA_KEY = 1, // eslint-disable-line no-unused-vars

/**
 * Bit flag indicating this wrapping key encrypted the data key.
 */
  WRAPPING_KEY_ENCRYPTED_DATA_KEY = (1 << 1), // eslint-disable-line no-unused-vars

/**
 * Bit flag indicating this wrapping key decrypted the data key.
 */
  WRAPPING_KEY_DECRYPTED_DATA_KEY = (1 << 2), // eslint-disable-line no-unused-vars

/**
 * Bit flag indicating this wrapping key signed the encryption context.
 */
  WRAPPING_KEY_SIGNED_ENC_CTX = (1 << 3), // eslint-disable-line no-unused-vars

/**
 * Bit flag indicating this wrapping key verified the signature of the encryption context.
 */
  WRAPPING_KEY_VERIFIED_ENC_CTX = (1 << 4), // eslint-disable-line no-unused-vars

  /* KeyringTraceFlags are organized here.
   * The three groupings are set, encrypt, and decrypt.
   * An unencrypted data key is set and is required to have a SET_FLAG.
   * For the encrypt path, the unencrypted data key must be generated.
   * For the decrypt path, the unencrypted data key must be decrypted.
   *
   * A encrypted data key must be encrypted
   * and the encryption context may be signed.
   *
   * When an encrypted data key is decrypted,
   * the encryption context may be verified.
   *
   * This organization is to keep a KeyringTrace for an encrypted data key
   * for listing the WRAPPING_KEY_VERIFIED_ENC_CTX flag.
   */

  ENCRYPT_FLAGS = WRAPPING_KEY_ENCRYPTED_DATA_KEY | WRAPPING_KEY_SIGNED_ENC_CTX, // eslint-disable-line no-unused-vars

  SET_FLAGS = WRAPPING_KEY_GENERATED_DATA_KEY | WRAPPING_KEY_DECRYPTED_DATA_KEY, // eslint-disable-line no-unused-vars

  DECRYPT_FLAGS = WRAPPING_KEY_DECRYPTED_DATA_KEY | WRAPPING_KEY_VERIFIED_ENC_CTX, // eslint-disable-line no-unused-vars
}
