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

// import { expect } from 'chai'
// import 'mocha'
// import { NodeDecryptionMaterial, NodeEncryptionMaterial, NodeAlgorithmSuite, AlgorithmSuiteIdentifier, KeyringTraceFlag } from '@aws-crypto/material-management'
// import { getEncryptHelper, getDecryptionHelper } from '../src/material_helpers'
// // @ts-ignore
// import { Decipheriv, Cipheriv } from 'crypto'

// describe('getEncryptHelper', () => {
//   it('first test', () => {
//     const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
//     const material = new NodeEncryptionMaterial(suite)
//     const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
//     const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_GENERATED_DATA_KEY }
//     material.setUnencryptedDataKey(dataKey, trace)

//     const helper = getEncryptHelper(material)
//     const getCipher = helper.kdfGetCipher()
//     const iv = new Uint8Array(12)
//     const cipher = getCipher(iv)
//     expect(cipher).to.be.instanceOf(Cipheriv)
//   })
// })

// describe('getDecryptionHelper', () => {
//   it('first test', () => {
//     const suite = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
//     const material = new NodeDecryptionMaterial(suite)
//     const dataKey = new Uint8Array(suite.keyLengthBytes).fill(1)
//     const trace = { keyNamespace: 'k', keyName: 'k', flags: KeyringTraceFlag.WRAPPING_KEY_DECRYPTED_DATA_KEY }
//     material.setUnencryptedDataKey(dataKey, trace)

//     const helper = getDecryptionHelper(material)
//     const getDecipher = helper.kdfGetDecipher()
//     const iv = new Uint8Array(12)
//     const decipher = getDecipher(iv)

//     expect(decipher).to.be.instanceOf(Decipheriv)
//   })
// })
