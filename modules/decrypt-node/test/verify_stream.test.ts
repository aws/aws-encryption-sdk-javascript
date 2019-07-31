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
import { VerifyStream } from '../src/verify_stream'
import { ParseHeaderStream } from '../src/parse_header_stream'
import * as fixtures from './fixtures'
import from from 'from2'
import { ContentType } from '@aws-crypto/serialize'
import { NodeAlgorithmSuite, AlgorithmSuiteIdentifier } from '@aws-crypto/material-management-node'

describe('VerifyStream', () => {
  it('can be created', () => {
    const test = new VerifyStream({})
    expect(test).to.be.instanceOf(VerifyStream)
  })

  it('Precondition: VerifyStream requires maxBodySize must be falsey or a number.', () => {
    expect(() => new VerifyStream({ maxBodySize: true } as any)).to.throw('Unsupported MaxBodySize.')
  })

  it('Precondition: The source must a ParseHeaderStream emit the required events.', () => {
    const notParseHeaderStream = from(() => {})
    const test = new VerifyStream({})
    expect(() => notParseHeaderStream.pipe(test)).to.throw('Unsupported source')
  })

  it('Precondition: If maxBodySize was set I can not buffer more data than maxBodySize.', () => {
    const source = new ParseHeaderStream({} as any)
    const test = new VerifyStream({ maxBodySize: 1 })
    source.pipe(test)
    // this is _just_ enough data to pass....
    source.emit('VerifyInfo', {
      headerInfo: {
        algorithmSuite: new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16),
        messageHeader: {
          messageId: Buffer.from('asdf'),
          contentType: ContentType.FRAMED_DATA,
          frameLength: 2
        }
      }
    })

    const buffer = Buffer.concat([
      fixtures.basicFrameHeader(),
      Buffer.from([1])
    ])
    expect(() => test._transform(buffer, 'binary', () => {})).to.throw('maxBodySize exceeded.')
  })

  it('Precondition: VerifyInfo must have initialized the stream.', () => {
    const test = new VerifyStream({})
    expect(() => test._transform(Buffer.from([1]), 'binary', () => {})).to.throw('VerifyStream not configured, VerifyInfo event not yet received.')
  })

  it('Check for early return (Postcondition): If there is no verify stream do not attempt to verify.', () => {
    // This works because there is no state, and any state would cause _flush to throw
    const test = new VerifyStream({})
    let called = false
    test._flush(() => {
      called = true
    })
    expect(called).to.equal(true)
  })
})
