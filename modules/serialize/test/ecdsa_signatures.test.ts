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

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import { der2raw, raw2der } from '../src/ecdsa_signature'
import { WebCryptoAlgorithmSuite, AlgorithmSuiteIdentifier } from '@aws-crypto/material-management'
import { concatBuffers } from '../src/concat_buffers'

/* Data for both verification examples
const dataToSign = new Uint8Array([1,2,3,4])
*/

/* Browser verification
const publicKeyBytes = new Uint8Array([4,199,199,40,132,29,178,63,39,29,51,216,142,122,137,115,70,152,91,198,68,95,101,88,187,240,227,232,177,5,206,158,174,156,228,250,254,167,216,195,179,21,136,7,14,50,154,73,49,222,215,184,15,42,108,247,118,126,164,207,62,168,64,30,63])
const webCryptoAlgorithm = { name: 'ECDSA', namedCurve: 'P-256' }
const extractable = false
const usages = ['verify']
const format = 'raw'
const publicKey = await crypto.subtle.importKey(format, publicKeyBytes, webCryptoAlgorithm, extractable, usages)
const algorithm = { name: 'ECDSA', hash: { name: 'SHA-256' } }
const isVerified = await crypto.subtle.verify(algorithm, publicKey, rawSignature, dataToSign)
*/

/* Node verification
const publicPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx8cohB2yPycdM9iOeolzRphbxkRf
ZVi78OPosQXOnq6c5Pr+p9jDsxWIBw4ymkkx3te4Dyps93Z+pM8+qEAePw==
-----END PUBLIC KEY-----
`
const v = createVerify('sha256')
v.update(dataToSign)
const isVerified = v.verify(publicPem, derSignature)
*/



const validSuite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256)
const rawSignature = new Uint8Array([22, 77, 187, 192, 175, 104, 2, 240, 55, 2, 6, 138, 103, 148, 214, 240, 244, 65, 224, 254, 60, 52, 218, 22, 250, 245, 216, 228, 151, 151, 220, 234, 125, 9, 97, 8, 132, 123, 79, 193, 216, 207, 214, 0, 73, 183, 149, 173, 26, 173, 251, 132, 140, 139, 44, 122, 11, 50, 163, 105, 138, 221, 223, 29])
const derSignature = new Uint8Array([48, 68, 2, 32, 22, 77, 187, 192, 175, 104, 2, 240, 55, 2, 6, 138, 103, 148, 214, 240, 244, 65, 224, 254, 60, 52, 218, 22, 250, 245, 216, 228, 151, 151, 220, 234, 2, 32, 125, 9, 97, 8, 132, 123, 79, 193, 216, 207, 214, 0, 73, 183, 149, 173, 26, 173, 251, 132, 140, 139, 44, 122, 11, 50, 163, 105, 138, 221, 223, 29])

describe('der2raw', () => {
  it('transform to raw signature', () => {
    const signature = der2raw(derSignature, validSuite)
    expect(signature).to.deep.equal(rawSignature)
  })

  it('Precondition: Do not attempt to RAW format if the suite does not support signing.', () => {
    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => der2raw(derSignature, suite)).to.throw()
  })
})

describe('raw2der', () => {
  it('transform to der signature', () => {
    const signature = raw2der(rawSignature, validSuite)
    expect(signature).to.deep.equal(derSignature)
  })

  it('Precondition: Do not attempt to DER format if the suite does not support signing.', () => {
    const suite = new WebCryptoAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => raw2der(rawSignature, suite)).to.throw()
  })
})
