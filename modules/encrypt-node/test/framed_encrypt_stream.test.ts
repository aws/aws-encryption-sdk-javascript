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

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { getFramedEncryptStream } from '../src/framed_encrypt_stream'

chai.use(chaiAsPromised)
const { expect } = chai

describe('getFramedEncryptStream', () => {
  it('can be created', () => {
    const getCipher: any = () => {}
    const test = getFramedEncryptStream(getCipher, {} as any, () => {})
    expect(test._transform).is.a('function')
  })

  it('Precondition: plaintextLength must be within bounds.', () => {
    const getCipher: any = () => {}
    expect(() => getFramedEncryptStream(getCipher, {} as any, () => {}, -1)).to.throw(Error, 'plaintextLength out of bounds.')
    expect(() => getFramedEncryptStream(getCipher, {} as any, () => {}, Number.MAX_SAFE_INTEGER + 1)).to.throw(Error, 'plaintextLength out of bounds.')

    /* Math is hard.
     * I want to make sure that I don't have an errant off by 1 error.
     */
    expect(() => getFramedEncryptStream(getCipher, {} as any, () => {}, Number.MAX_SAFE_INTEGER)).to.not.throw(Error)
  })

  it('Precondition: Must not process more than plaintextLength.', () => {
    const getCipher: any = () => {}
    const test = getFramedEncryptStream(getCipher, { } as any, () => {}, 8)

    expect(() => test._transform(Buffer.from(Array(9)), 'binary', () => {})).to.throw(Error, 'Encrypted data exceeded plaintextLength.')
  })

  it('Check for early return (Postcondition): Have not accumulated a frame.', () => {
    const getCipher: any = () => {}
    const frameLength = 10
    const test = getFramedEncryptStream(getCipher, { frameLength } as any, () => {})

    let called = false
    test._transform(Buffer.from(Array(9)), 'binary', () => {
      called = true
    })

    expect(called).to.equal(true)
  })
})
