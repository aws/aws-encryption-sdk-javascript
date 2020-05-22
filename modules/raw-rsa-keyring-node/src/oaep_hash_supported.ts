// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* oaepHash support was added in Node.js v12.9.1 (https://github.com/nodejs/node/pull/28335)
 * However, the integration tests need to be able to verify functionality on other versions.
 * There are no constants to sniff,
 * and looking at the version would not catch back-ports.
 * So I simply try the function.
 * However there is a rub as the test might seem backwards.
 * Sending an invalid hash to the version that supports oaepHash will throw an error.
 * But sending an invalid hash to a version that does not support oaepHash will be ignored.
 */

import { needs } from '@aws-crypto/material-management-node'

import { constants, publicEncrypt } from 'crypto'

export const oaepHashSupported = (function () {
  const key =
    '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs7RoNYEPAIws89VV+kra\nrVv/4wbdmUAaAKWgWuxZi5na9GJSmnhCkqyLRm7wPbQY4LCoa5/IMUxkHLsYDPdu\nudY0Qm0GcoxOlvJKHYo4RjF7HyiS34D6dvyO4Gd3aq0mZHoxSGCxW/7hf03wEMzc\niVJXWHXhaI0lD6nrzIEgLrE4L+3V2LeAQjvZsTKd+bYMqeZOL2syiVVIAU8POwAG\nGVBroJoveFm/SUp6lCiN0M2kTeyQA2ax3QTtZSAa8nwrI7U52XOzVmdMicJsy2Pg\nuW98te3MuODdK24yNkHIkYameP/Umf/SJshUJQd5a/TUp3XE+HhOWAumx22tIDlC\nvZS11cuk2fp0WeHUnXaC19N5qWKfvHEKSugzty/z3lGP7ItFhrF2X1qJHeAAsL11\nkjo6Lc48KsE1vKvbnW4VLyB3wdNiVvmUNO29tPXwaR0Q5Gbr3jk3nUzdkEHouHWQ\n41lubOHCCBN3V13mh/MgtNhESHjfmmOnh54ErD9saA1d7CjTf8g2wqmjEqvGSW6N\nq7zhcWR2tp1olflS7oHzul4/I3hnkfL6Kb2xAWWaQKvg3mtsY2OPlzFEP0tR5UcH\nPfp5CeS1Xzg7hN6vRICW6m4l3u2HJFld2akDMm1vnSz8RCbPW7jp7YBxUkWJmypM\ntG7Yv2aGZXGbUtM8o1cZarECAwEAAQ==\n-----END PUBLIC KEY-----'

  const oaepHash = 'i_am_not_valid'
  try {
    // @ts-ignore
    publicEncrypt(
      { key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash },
      Buffer.from([1, 2, 3, 4])
    )
    /* See note above,
     * only versions that support oaepHash will respond.
     * So the only way I can get here is if the option was ignored.
     */
    return false
  } catch (ex) {
    needs(
      ex.code === 'ERR_OSSL_EVP_INVALID_DIGEST',
      'Unexpected error testing oaepHash.'
    )
    return true
  }
})()
