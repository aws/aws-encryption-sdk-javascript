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

import { NodeCryptographicMaterialsManager, AlgorithmSuiteIdentifier } from '@aws-crypto/material-management-node'
import { KmsKeyringNode, getKmsClient } from '@aws-crypto/kms-keyring-node'
import { encryptStream } from '@aws-crypto/encrypt-node'
import { decryptStream } from '@aws-crypto/decrypt-node'
import { finished } from 'stream'
import { createReadStream, createWriteStream } from 'fs'
import { promisify } from 'util'
const finishedAsync = promisify(finished)

export async function kmsStreamTest () {
  const clientProvider = getKmsClient
  const generatorKmsKey = 'arn:aws:kms:us-west-2:658956600833:alias/EncryptDecrypt'
  const keyring = new KmsKeyringNode({ clientProvider, generatorKmsKey })

  const cmm = new NodeCryptographicMaterialsManager(keyring)
  const suiteId = AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16

  const stream = createReadStream('../package.json')
    .pipe(encryptStream(cmm, { suiteId }))
    .pipe(decryptStream(cmm))
    .pipe(createWriteStream('../package.json.decrypt'))

  return finishedAsync(stream)
}
