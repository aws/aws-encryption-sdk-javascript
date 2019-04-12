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

import { KmsKeyringNode } from '@aws-crypto/kms-keyring-node'
import { encrypt } from '@aws-crypto/encrypt-node'
import { decrypt } from '@aws-crypto/decrypt-node'
import { NodeCryptographicMaterialsManager } from '@aws-crypto/material-management-node'

export async function kmsSimpleTest () {
  const generatorKeyId = 'arn:aws:kms:us-west-2:111122223333:alias/EncryptDecrypt'
  const keyIds = ['arn:aws:kms:us-west-2:111122223333:alias/EncryptDecrypt', 'arn:aws:kms:us-west-2:111122223333:alias/EncryptDecrypt']
  const keyring = new KmsKeyringNode({ generatorKeyId, keyIds })

  const cmm = new NodeCryptographicMaterialsManager(keyring)

  const context = { some: 'context' }
  const plaintext = 'asdf'

  const { ciphertext } = await encrypt(cmm, plaintext, { context })

  const cleartext = await decrypt(cmm, ciphertext)

  return { plaintext, ciphertext, cleartext }
}
