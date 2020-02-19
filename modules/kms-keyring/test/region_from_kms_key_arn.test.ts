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
import { regionFromKmsKeyArn } from '../src/region_from_kms_key_arn'

describe('regionFromKmsKeyArn', () => {
  it('return region', () => {
    const test1 = regionFromKmsKeyArn('arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012')
    expect(test1).to.equal('us-east-1')
    const test2 = regionFromKmsKeyArn('arn:aws:kms:us-east-1:123456789012:alias/example-alias')
    expect(test2).to.equal('us-east-1')
    const test3 = regionFromKmsKeyArn('arn:aws:kms:us-east-1:123456789012:12345678-1234-1234-1234-123456789012')
    expect(test3).to.equal('us-east-1')
  })

  it('return empty string for an alias', () => {
    expect(regionFromKmsKeyArn('alias/example-alias')).to.equal('')
    expect(regionFromKmsKeyArn('alias:example-alias')).to.equal('')
    /* using a keyId is confusing.
     * It should work but is not recommended.
     * Figuring out what region they CMK exist in is difficult.
     */
    expect(regionFromKmsKeyArn('key/12345678-1234-1234-1234-123456789012')).to.equal('')
    expect(regionFromKmsKeyArn('key:12345678-1234-1234-1234-123456789012')).to.equal('')
  })

  it('Precondition: A KMS key arn must be a string.', () => {
    const bad = {} as any
    expect(() => regionFromKmsKeyArn(bad)).to.throw()
  })

  it('Postcondition: The ARN must be well formed.', () => {
    expect(() => regionFromKmsKeyArn('')).to.throw()
    expect(() => regionFromKmsKeyArn('NOTarn:aws:kms:us-east-1:123456789012:alias/example-alias')).to.throw()
    // empty partition
    expect(() => regionFromKmsKeyArn('arn::kms:us-east-1:123456789012:alias/example-alias')).to.throw()
    expect(() => regionFromKmsKeyArn('arn:aws:NOTkms:us-east-1:123456789012:alias/example-alias')).to.throw()
    // empty region
    expect(() => regionFromKmsKeyArn('arn:aws:kms::123456789012:alias/example-alias')).to.throw()

    // no resource type
    expect(() => regionFromKmsKeyArn('example-alias')).to.throw()
    // invalid resource type
    expect(() => regionFromKmsKeyArn('something/example-alias')).to.throw()
    expect(() => regionFromKmsKeyArn('something:example-alias')).to.throw()
    // invalid delimiter
    expect(() => regionFromKmsKeyArn('alias_example-alias')).to.throw()
    expect(() => regionFromKmsKeyArn('key_12345678-1234-1234-1234-123456789012')).to.throw()
  })
})
