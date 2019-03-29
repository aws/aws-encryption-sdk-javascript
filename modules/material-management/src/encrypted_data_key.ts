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

import { readOnlyBinaryProperty, readOnlyProperty, frozenClass } from './immutable_class'
import { needs } from './needs'

/*
 * This public interface to the encrypted data key (EDK) objects is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */

export interface IEncryptedDataKey extends Readonly<{
  providerInfo: string
  providerId: string
  encryptedDataKey: Uint8Array
}>{}

export class EncryptedDataKey {
  readonly providerInfo!: string
  readonly providerId!: string
  readonly encryptedDataKey!: Uint8Array

  constructor (edkInput: IEncryptedDataKey) {
    const { providerInfo, providerId, encryptedDataKey } = edkInput
    needs(
      typeof providerInfo === 'string' && providerInfo &&
      typeof providerId === 'string' && providerId &&
      encryptedDataKey instanceof Uint8Array && encryptedDataKey.byteLength,
      'Malformed encrypted data key')

    readOnlyProperty<EncryptedDataKey, 'providerInfo'>(this, 'providerInfo', providerInfo)
    readOnlyProperty<EncryptedDataKey, 'providerId'>(this, 'providerId', providerId)
    readOnlyBinaryProperty(this, 'encryptedDataKey', encryptedDataKey)

    Object.setPrototypeOf(this, EncryptedDataKey.prototype)
    Object.freeze(this)
  }
}

frozenClass(EncryptedDataKey)
