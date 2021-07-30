// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { der2raw, raw2der } from '../src/ecdsa_signature'
import {
  WebCryptoAlgorithmSuite,
  AlgorithmSuiteIdentifier,
} from '@aws-crypto/material-management'

/*
 * This turns out the be very tricky.
 * Test vectors are the path to your success.
 * In case you need to create more,
 * I am reproducing the parts needed to copy/paste yourself to victory.
 *
 * DER encoding stores integers as signed values.
 * This means if the first bit is a 1,
 * the value will be interpreted as negative.
 * So an extra byte needs to be added on.
 * This is a problem because "raw" encoding is just r|s.
 * Without this "extra logic" a given DER signature `sig` *may*
 * raw2der(der2raw(sig)) !== sig
 * see: https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf 8.3

# Data for all verification examples
```
const dataToSign = new Uint8Array([1,2,3,4])
```

# Generating a key

## For browsers:
```
const { publicKey, privateKey } = await window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'])
// Set variables so you can import
const publicKeyBytes = await window.crypto.subtle.exportKey('spki', publicKey)
const privateKeyBytes = await window.crypto.subtle.exportKey('pkcs8', privateKey)
```

## For node.js (v12)
```
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {namedCurve: 'secp384r1' })
// Set variables so you can import
const publicKeyBytes = publicKey.export({ type: 'spki', format: 'der' })
const privateKeyBytes = privateKey.export({ type: 'pkcs8', format: 'der' })
```

### Helpful REPL lines to transfer data :)
```
'const publicKeyBytes = new Uint8Array(' + JSON.stringify([...new Uint8Array(publicKeyBytes)]) + ')'
'const privateKeyBytes = new Uint8Array(' + JSON.stringify([...new Uint8Array(privateKeyBytes)]) + ')'
```

# Import keys from a different environment

## For browsers, from node.js
```
const publicKey = await window.crypto.subtle.importKey('spki', publicKeyBytes, { name: 'ECDSA', namedCurve: 'P-384' }, true, ['verify'])
const privateKey = await window.crypto.subtle.importKey('pkcs8', privateKeyBytes, { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign'])
```

## For node.js (v12) from browsers
```
const publicKey = crypto.createPublicKey({key: publicKeyBytes, format: 'der', type: 'spki'})
const privateKey = crypto.createPrivateKey({key: privateKeyBytes, format: 'der', type: 'pkcs8'})
```

# Sign the data
## For browsers:
```
const signature = await window.crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' } }, privateKey, dataToSign)
```

## For node.js v12
```
const signature = crypto.createSign('sha384').update(dataToSign).sign(privateKey)
```

# Verify the signature
## For browsers:
```
const verify = await window.crypto.subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' } }, publicKey, signature, dataToSign)
```

## For node.js v12
```
const isVerified = crypto.createVerify('sha384').update(dataToSign).verify(publicKey, signature)
```
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

const validSuite = new WebCryptoAlgorithmSuite(
  AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
)
const rawSignature = new Uint8Array([
  22, 77, 187, 192, 175, 104, 2, 240, 55, 2, 6, 138, 103, 148, 214, 240, 244,
  65, 224, 254, 60, 52, 218, 22, 250, 245, 216, 228, 151, 151, 220, 234, 125, 9,
  97, 8, 132, 123, 79, 193, 216, 207, 214, 0, 73, 183, 149, 173, 26, 173, 251,
  132, 140, 139, 44, 122, 11, 50, 163, 105, 138, 221, 223, 29,
])
const derSignature = new Uint8Array([
  48, 68, 2, 32, 22, 77, 187, 192, 175, 104, 2, 240, 55, 2, 6, 138, 103, 148,
  214, 240, 244, 65, 224, 254, 60, 52, 218, 22, 250, 245, 216, 228, 151, 151,
  220, 234, 2, 32, 125, 9, 97, 8, 132, 123, 79, 193, 216, 207, 214, 0, 73, 183,
  149, 173, 26, 173, 251, 132, 140, 139, 44, 122, 11, 50, 163, 105, 138, 221,
  223, 29,
])

const invalidLengthRawSignature = new Uint8Array([
  0, 22, 77, 187, 192, 175, 104, 2, 240, 55, 2, 6, 138, 103, 148, 214, 240, 244,
  65, 224, 254, 60, 52, 218, 22, 250, 245, 216, 228, 151, 151, 220, 234, 125, 9,
  97, 8, 132, 123, 79, 193, 216, 207, 214, 0, 73, 183, 149, 173, 26, 173, 251,
  132, 140, 139, 44, 122, 11, 50, 163, 105, 138, 221, 223, 29, 0,
])

/*
// All signatures should be verified with this public key (spki in bytes)
const publicKeyBytes = new Uint8Array([48,118,48,16,6,7,42,134,72,206,61,2,1,6,5,43,129,4,0,34,3,98,0,4,182,142,16,181,73,22,77,38,171,216,20,142,20,154,218,20,31,70,13,88,242,169,247,248,184,238,221,100,191,26,82,176,137,96,163,242,244,215,25,250,144,157,65,246,201,220,219,188,122,115,129,227,74,201,236,240,93,173,108,36,49,249,149,224,67,76,66,192,255,173,90,184,124,191,154,165,137,251,173,181,109,109,75,167,34,202,198,114,192,197,215,224,199,45,105,126])
*/

/*
  The following may be useful along with the above code to create additional test vectors.
```
function test() {
  let i = 100
  while (i--) {
    const sig = crypto.createSign('sha384').update(dataToSign).sign(privateKey)
    if ((sig[4] === 0 ? sig[56] : sig[55]) === 128) return sig
    if (sig[5] === 128) return sig
  }
}
```
*/

/* DER signatures for SHA384_ECDSA_P384 that exhibit different lengths,
 * and padding of r and s.
 */
// length == 102
const derSigNoPadding = new Uint8Array([
  48, 100, 2, 48, 125, 32, 154, 168, 112, 11, 187, 171, 135, 119, 83, 66, 69,
  164, 226, 80, 39, 176, 112, 210, 72, 159, 201, 242, 110, 212, 158, 170, 99,
  155, 80, 29, 99, 77, 158, 81, 170, 46, 116, 246, 137, 197, 82, 112, 70, 36,
  196, 49, 2, 48, 117, 43, 254, 192, 131, 207, 80, 1, 152, 238, 154, 139, 42,
  81, 244, 230, 42, 114, 137, 98, 127, 86, 166, 26, 172, 80, 132, 251, 97, 249,
  4, 39, 47, 250, 132, 44, 187, 235, 197, 157, 56, 216, 39, 130, 69, 46, 185,
  150,
])
const rawSigNoPadding = new Uint8Array([
  125, 32, 154, 168, 112, 11, 187, 171, 135, 119, 83, 66, 69, 164, 226, 80, 39,
  176, 112, 210, 72, 159, 201, 242, 110, 212, 158, 170, 99, 155, 80, 29, 99, 77,
  158, 81, 170, 46, 116, 246, 137, 197, 82, 112, 70, 36, 196, 49, 117, 43, 254,
  192, 131, 207, 80, 1, 152, 238, 154, 139, 42, 81, 244, 230, 42, 114, 137, 98,
  127, 86, 166, 26, 172, 80, 132, 251, 97, 249, 4, 39, 47, 250, 132, 44, 187,
  235, 197, 157, 56, 216, 39, 130, 69, 46, 185, 150,
])

// length == 103, r is padded
const derSigRPadded1 = new Uint8Array([
  48, 101, 2, 49, 0, 163, 81, 253, 131, 61, 166, 239, 242, 68, 133, 70, 219,
  243, 67, 220, 94, 57, 115, 92, 119, 17, 93, 152, 78, 78, 177, 110, 48, 164,
  12, 53, 146, 223, 8, 57, 108, 177, 237, 187, 165, 39, 162, 214, 193, 112, 220,
  132, 13, 2, 48, 10, 2, 53, 95, 195, 68, 6, 79, 110, 220, 215, 130, 204, 182,
  125, 44, 47, 198, 226, 17, 115, 207, 22, 89, 113, 18, 90, 63, 0, 105, 104,
  221, 159, 156, 17, 168, 95, 96, 254, 88, 45, 120, 223, 180, 12, 44, 118, 18,
])

const rawSigRPadded1 = new Uint8Array([
  163, 81, 253, 131, 61, 166, 239, 242, 68, 133, 70, 219, 243, 67, 220, 94, 57,
  115, 92, 119, 17, 93, 152, 78, 78, 177, 110, 48, 164, 12, 53, 146, 223, 8, 57,
  108, 177, 237, 187, 165, 39, 162, 214, 193, 112, 220, 132, 13, 10, 2, 53, 95,
  195, 68, 6, 79, 110, 220, 215, 130, 204, 182, 125, 44, 47, 198, 226, 17, 115,
  207, 22, 89, 113, 18, 90, 63, 0, 105, 104, 221, 159, 156, 17, 168, 95, 96,
  254, 88, 45, 120, 223, 180, 12, 44, 118, 18,
])

// length == 103, s is padded
const derSigSPadded1 = new Uint8Array([
  48, 101, 2, 48, 13, 237, 65, 195, 0, 118, 121, 114, 12, 187, 102, 24, 62, 8,
  42, 43, 27, 18, 27, 123, 222, 46, 84, 53, 255, 198, 169, 180, 206, 77, 60, 3,
  171, 209, 129, 25, 245, 157, 197, 128, 191, 153, 226, 52, 170, 3, 93, 180, 2,
  49, 0, 191, 191, 7, 215, 111, 31, 5, 75, 245, 134, 50, 255, 118, 224, 243,
  133, 233, 162, 55, 22, 203, 124, 69, 231, 1, 190, 191, 175, 158, 82, 80, 168,
  172, 29, 97, 13, 141, 126, 184, 238, 159, 214, 213, 92, 114, 94, 61, 82,
])
const rawSigSPadded1 = new Uint8Array([
  13, 237, 65, 195, 0, 118, 121, 114, 12, 187, 102, 24, 62, 8, 42, 43, 27, 18,
  27, 123, 222, 46, 84, 53, 255, 198, 169, 180, 206, 77, 60, 3, 171, 209, 129,
  25, 245, 157, 197, 128, 191, 153, 226, 52, 170, 3, 93, 180, 191, 191, 7, 215,
  111, 31, 5, 75, 245, 134, 50, 255, 118, 224, 243, 133, 233, 162, 55, 22, 203,
  124, 69, 231, 1, 190, 191, 175, 158, 82, 80, 168, 172, 29, 97, 13, 141, 126,
  184, 238, 159, 214, 213, 92, 114, 94, 61, 82,
])

// length == 104 both r and s are padded
const derSigBothSandRPadded = new Uint8Array([
  48, 102, 2, 49, 0, 161, 31, 228, 163, 249, 149, 236, 238, 15, 140, 163, 28,
  152, 199, 168, 83, 187, 60, 79, 26, 71, 243, 120, 0, 44, 200, 217, 82, 162,
  181, 168, 194, 181, 56, 20, 193, 213, 40, 112, 59, 13, 254, 55, 177, 231, 189,
  128, 71, 2, 49, 0, 241, 232, 224, 60, 113, 203, 248, 143, 34, 63, 98, 221,
  156, 143, 58, 106, 169, 169, 63, 126, 103, 145, 63, 246, 255, 32, 74, 11, 197,
  255, 13, 244, 105, 188, 157, 210, 200, 36, 140, 218, 1, 115, 99, 255, 212, 71,
  156, 38,
])
const rawSigBothSandRPadded = new Uint8Array([
  161, 31, 228, 163, 249, 149, 236, 238, 15, 140, 163, 28, 152, 199, 168, 83,
  187, 60, 79, 26, 71, 243, 120, 0, 44, 200, 217, 82, 162, 181, 168, 194, 181,
  56, 20, 193, 213, 40, 112, 59, 13, 254, 55, 177, 231, 189, 128, 71, 241, 232,
  224, 60, 113, 203, 248, 143, 34, 63, 98, 221, 156, 143, 58, 106, 169, 169, 63,
  126, 103, 145, 63, 246, 255, 32, 74, 11, 197, 255, 13, 244, 105, 188, 157,
  210, 200, 36, 140, 218, 1, 115, 99, 255, 212, 71, 156, 38,
])

// Suite AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
const derSigSPadded2 = new Uint8Array([
  48, 101, 2, 49, 0, 206, 207, 127, 87, 135, 99, 138, 178, 184, 182, 16, 31, 28,
  196, 105, 124, 25, 66, 150, 72, 89, 3, 170, 18, 226, 212, 211, 102, 87, 24,
  100, 142, 19, 231, 192, 75, 170, 233, 113, 106, 52, 106, 218, 240, 88, 104,
  184, 244, 2, 48, 0, 243, 34, 43, 43, 42, 51, 175, 155, 222, 78, 148, 98, 211,
  255, 81, 171, 101, 118, 207, 128, 50, 101, 16, 181, 174, 34, 59, 245, 237,
  246, 92, 103, 13, 144, 249, 54, 248, 1, 74, 205, 79, 83, 52, 249, 106, 46,
  185,
])
const rawSigSPadded2 = new Uint8Array([
  206, 207, 127, 87, 135, 99, 138, 178, 184, 182, 16, 31, 28, 196, 105, 124, 25,
  66, 150, 72, 89, 3, 170, 18, 226, 212, 211, 102, 87, 24, 100, 142, 19, 231,
  192, 75, 170, 233, 113, 106, 52, 106, 218, 240, 88, 104, 184, 244, 0, 243, 34,
  43, 43, 42, 51, 175, 155, 222, 78, 148, 98, 211, 255, 81, 171, 101, 118, 207,
  128, 50, 101, 16, 181, 174, 34, 59, 245, 237, 246, 92, 103, 13, 144, 249, 54,
  248, 1, 74, 205, 79, 83, 52, 249, 106, 46, 185,
])

// Suite AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
const derSigSPadded3 = new Uint8Array([
  48, 100, 2, 48, 3, 174, 112, 110, 38, 199, 245, 110, 255, 244, 216, 238, 8,
  146, 175, 220, 53, 45, 2, 91, 102, 60, 134, 249, 53, 226, 56, 240, 122, 166,
  67, 33, 106, 207, 9, 53, 2, 92, 141, 76, 160, 118, 192, 12, 170, 162, 98, 175,
  2, 48, 0, 229, 249, 27, 0, 39, 69, 9, 104, 23, 106, 211, 90, 91, 144, 34, 124,
  56, 104, 187, 224, 172, 166, 3, 130, 202, 230, 120, 84, 197, 8, 175, 200, 37,
  52, 206, 23, 210, 129, 215, 103, 252, 66, 61, 47, 179, 31, 191,
])
const rawSigSPadded3 = new Uint8Array([
  3, 174, 112, 110, 38, 199, 245, 110, 255, 244, 216, 238, 8, 146, 175, 220, 53,
  45, 2, 91, 102, 60, 134, 249, 53, 226, 56, 240, 122, 166, 67, 33, 106, 207, 9,
  53, 2, 92, 141, 76, 160, 118, 192, 12, 170, 162, 98, 175, 0, 229, 249, 27, 0,
  39, 69, 9, 104, 23, 106, 211, 90, 91, 144, 34, 124, 56, 104, 187, 224, 172,
  166, 3, 130, 202, 230, 120, 84, 197, 8, 175, 200, 37, 52, 206, 23, 210, 129,
  215, 103, 252, 66, 61, 47, 179, 31, 191,
])

// Suite AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
const derSigRPadded2 = new Uint8Array([
  48, 99, 2, 47, 26, 164, 142, 247, 57, 120, 102, 219, 166, 194, 246, 139, 155,
  151, 31, 222, 39, 27, 176, 125, 4, 225, 191, 115, 206, 227, 133, 126, 132, 71,
  27, 95, 99, 34, 68, 77, 155, 175, 77, 111, 199, 68, 75, 181, 35, 103, 80, 2,
  48, 124, 106, 76, 171, 45, 237, 33, 38, 6, 243, 85, 223, 236, 216, 120, 53,
  193, 229, 52, 139, 42, 178, 10, 217, 25, 236, 232, 148, 53, 85, 68, 73, 105,
  97, 134, 176, 51, 81, 52, 118, 213, 36, 195, 16, 187, 114, 85, 182,
])
const rawSigRPadded2 = new Uint8Array([
  0, 26, 164, 142, 247, 57, 120, 102, 219, 166, 194, 246, 139, 155, 151, 31,
  222, 39, 27, 176, 125, 4, 225, 191, 115, 206, 227, 133, 126, 132, 71, 27, 95,
  99, 34, 68, 77, 155, 175, 77, 111, 199, 68, 75, 181, 35, 103, 80, 124, 106,
  76, 171, 45, 237, 33, 38, 6, 243, 85, 223, 236, 216, 120, 53, 193, 229, 52,
  139, 42, 178, 10, 217, 25, 236, 232, 148, 53, 85, 68, 73, 105, 97, 134, 176,
  51, 81, 52, 118, 213, 36, 195, 16, 187, 114, 85, 182,
])

/* This vector has the "first byte" of r === 128.
 * This means that the "first bit" of r === 1.
 * This means the DER signature is padded.
 */
const derSigRonBoundary = new Uint8Array([
  48, 102, 2, 49, 0, 128, 193, 160, 46, 142, 254, 87, 100, 216, 114, 75, 154,
  209, 17, 184, 155, 141, 178, 118, 99, 34, 161, 229, 195, 144, 1, 183, 41, 165,
  115, 107, 123, 234, 39, 90, 43, 247, 108, 227, 88, 144, 107, 230, 39, 103,
  213, 174, 206, 2, 49, 0, 209, 70, 36, 78, 124, 248, 10, 77, 80, 102, 88, 38,
  166, 138, 237, 192, 93, 189, 17, 157, 57, 203, 245, 93, 178, 19, 206, 31, 13,
  117, 4, 241, 176, 107, 169, 23, 39, 71, 127, 32, 210, 157, 82, 115, 163, 177,
  42, 74,
])
const rawSigRonBoundary = new Uint8Array([
  128, 193, 160, 46, 142, 254, 87, 100, 216, 114, 75, 154, 209, 17, 184, 155,
  141, 178, 118, 99, 34, 161, 229, 195, 144, 1, 183, 41, 165, 115, 107, 123,
  234, 39, 90, 43, 247, 108, 227, 88, 144, 107, 230, 39, 103, 213, 174, 206,
  209, 70, 36, 78, 124, 248, 10, 77, 80, 102, 88, 38, 166, 138, 237, 192, 93,
  189, 17, 157, 57, 203, 245, 93, 178, 19, 206, 31, 13, 117, 4, 241, 176, 107,
  169, 23, 39, 71, 127, 32, 210, 157, 82, 115, 163, 177, 42, 74,
])

/* This vector has the "first byte" of s === 128.
 * This means that the "first bit" of s === 1.
 * This means the DER signature is padded.
 */
const derSigSonBoundary = new Uint8Array([
  48, 101, 2, 48, 99, 9, 32, 95, 74, 230, 183, 174, 87, 124, 144, 130, 171, 98,
  39, 162, 23, 207, 58, 218, 73, 183, 190, 173, 107, 46, 130, 60, 185, 45, 245,
  81, 57, 191, 60, 41, 6, 8, 68, 241, 221, 25, 122, 145, 25, 229, 148, 158, 2,
  49, 0, 128, 50, 250, 23, 18, 25, 233, 203, 214, 199, 87, 201, 51, 187, 231,
  99, 99, 114, 101, 252, 197, 48, 94, 2, 1, 12, 154, 225, 237, 112, 63, 95, 149,
  14, 159, 190, 177, 241, 121, 75, 133, 77, 148, 78, 11, 34, 215, 58,
])
const rawSigSonBoundary = new Uint8Array([
  99, 9, 32, 95, 74, 230, 183, 174, 87, 124, 144, 130, 171, 98, 39, 162, 23,
  207, 58, 218, 73, 183, 190, 173, 107, 46, 130, 60, 185, 45, 245, 81, 57, 191,
  60, 41, 6, 8, 68, 241, 221, 25, 122, 145, 25, 229, 148, 158, 128, 50, 250, 23,
  18, 25, 233, 203, 214, 199, 87, 201, 51, 187, 231, 99, 99, 114, 101, 252, 197,
  48, 94, 2, 1, 12, 154, 225, 237, 112, 63, 95, 149, 14, 159, 190, 177, 241,
  121, 75, 133, 77, 148, 78, 11, 34, 215, 58,
])

describe('der2raw', () => {
  it('transform to raw signature', () => {
    const signature = der2raw(derSignature, validSuite)
    expect(signature).to.deep.equal(rawSignature)
  })

  it('Precondition: Do not attempt to RAW format if the suite does not support signing.', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => der2raw(derSignature, suite)).to.throw()
  })

  describe('padding', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )

    const commitSuite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    )

    it('No Padding', () => {
      expect(der2raw(derSigNoPadding, suite)).to.deep.equal(rawSigNoPadding)
    })

    it('R padded', () => {
      expect(der2raw(derSigRPadded1, suite)).to.deep.equal(rawSigRPadded1)
    })

    it('S padded', () => {
      expect(der2raw(derSigSPadded1, suite)).to.deep.equal(rawSigSPadded1)
    })

    it('R and S padded', () => {
      expect(der2raw(derSigBothSandRPadded, suite)).to.deep.equal(
        rawSigBothSandRPadded
      )
    })

    it('S padded', () => {
      expect(der2raw(derSigSPadded2, commitSuite)).to.deep.equal(rawSigSPadded2)
    })

    it('S padded (with no padding in DER)', () => {
      expect(der2raw(derSigSPadded3, commitSuite)).to.deep.equal(rawSigSPadded3)
    })

    it('R padded', () => {
      expect(der2raw(derSigRPadded2, commitSuite)).to.deep.equal(rawSigRPadded2)
    })

    it('transform to der signature with with r padded, but r is on the padding boundary', () => {
      expect(der2raw(derSigRonBoundary, suite)).to.deep.equal(rawSigRonBoundary)
    })

    it('transform to der signature with s padded, but s is on the padding boundary', () => {
      expect(der2raw(derSigSonBoundary, suite)).to.deep.equal(rawSigSonBoundary)
    })
  })
})

describe('raw2der', () => {
  it('transform to der signature', () => {
    const signature = raw2der(rawSignature, validSuite)
    expect(signature).to.deep.equal(derSignature)
  })

  it('Precondition: Do not attempt to DER format if the suite does not support signing.', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16
    )
    expect(() => raw2der(rawSignature, suite)).to.throw()
  })

  const suite = new WebCryptoAlgorithmSuite(
    AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
  )

  it('Precondition: The total raw signature length is twice the key length bytes.', () => {
    expect(() => raw2der(invalidLengthRawSignature, suite)).to.throw(
      'Malformed signature.'
    )
  })

  describe('padding', () => {
    const suite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    )

    const commitSuite = new WebCryptoAlgorithmSuite(
      AlgorithmSuiteIdentifier.ALG_AES256_GCM_IV12_TAG16_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    )

    it('No Padding', () => {
      expect(raw2der(rawSigNoPadding, suite)).to.deep.equal(derSigNoPadding)
    })

    it('R padded', () => {
      expect(raw2der(rawSigRPadded1, suite)).to.deep.equal(derSigRPadded1)
    })

    it('S padded', () => {
      expect(raw2der(rawSigSPadded1, suite)).to.deep.equal(derSigSPadded1)
    })

    it('R and S padded', () => {
      expect(raw2der(rawSigBothSandRPadded, suite)).to.deep.equal(
        derSigBothSandRPadded
      )
    })

    it('S padded', () => {
      expect(raw2der(rawSigSPadded2, commitSuite)).to.deep.equal(derSigSPadded2)
    })

    it('S padded (with no padding in DER)', () => {
      expect(raw2der(rawSigSPadded3, commitSuite)).to.deep.equal(derSigSPadded3)
    })

    it('R padded', () => {
      expect(raw2der(rawSigRPadded2, commitSuite)).to.deep.equal(derSigRPadded2)
    })

    it('transform to der signature with with r padded, but r is on the padding boundary', () => {
      expect(raw2der(rawSigRonBoundary, suite)).to.deep.equal(derSigRonBoundary)
    })

    it('transform to der signature with s padded, but s is on the padding boundary', () => {
      expect(raw2der(rawSigSonBoundary, suite)).to.deep.equal(derSigSonBoundary)
    })
  })
})
