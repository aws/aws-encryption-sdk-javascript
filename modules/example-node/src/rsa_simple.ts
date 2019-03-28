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

import { NodeCryptographicMaterialsManager } from '@aws-crypto/material-management-node'
import { RsaKeyringNode } from '@aws-crypto/rsa-keyring-node'
import { encrypt } from '@aws-crypto/encrypt-node'
import { decrypt } from '@aws-crypto/decrypt-node'

import { generateKeyPair } from 'crypto'
import { promisify } from 'util'
const generateKeyPairAsync = promisify(generateKeyPair)

/**
 * This function is an example of using the RsaKeyringNode
 * to encrypt and decrypt a simple string
 */
export async function rsaTest () {
  const keyName = 'rsa-name'
  const keyNamespace = 'rsa-namespce'
  // You should get your key pairs from wherever you are storing them.
  const rsaKey = await generateRsaKeys()

  const keyring = new RsaKeyringNode({ keyName, keyNamespace, rsaKey })

  const cmm = new NodeCryptographicMaterialsManager(keyring)

  const context = { some: 'context' }
  const cleartext = 'asdf'

  const { ciphertext } = await encrypt(cmm, cleartext, { context })

  const { plaintext } = await decrypt(cmm, ciphertext)

  return { plaintext, ciphertext, cleartext }
}

/**
 * This is a helper function to generate an RSA key pair and
 * not store a private key in source that someone might
 * copy and use in production code.
 */
async function generateRsaKeys () {
  const modulusLength = 3072
  const publicKeyEncoding = { type: 'pkcs1', format: 'pem' }
  const privateKeyEncoding = { type: 'pkcs1', format: 'pem' }
  // @ts-ignore
  return generateKeyPairAsync('rsa', {
    modulusLength,
    publicKeyEncoding,
    privateKeyEncoding
  })
}
