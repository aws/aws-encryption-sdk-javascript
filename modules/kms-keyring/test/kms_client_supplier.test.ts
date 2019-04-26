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
import { getClient, limitRegions, excludeRegions, cacheClients } from '../src/kms_client_supplier'

describe('getClient', () => {
  it('return a client', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
        this.config = { region }
      }
    }
    const getKmsClient = getClient(TestKMS)
    const test = getKmsClient(region)
    expect(test).instanceOf(TestKMS)
    expect(assertCount).to.equal(1)
  })

  it('passes default config values', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor (config: any) {
        expect(config.region).to.equal(region)
        expect(config.extra).to.equal('value')
        assertCount++
        this.config = { region }
      }
    }
    const getKmsClient = getClient(TestKMS, { extra: 'value' } as any)
    const test = getKmsClient(region)
    expect(test).instanceOf(TestKMS)
    expect(assertCount).to.equal(1)
  })

  it('will not override region', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
        this.config = { region }
      }
    }
    const getKmsClient = getClient(TestKMS, { region: 'no-a-region' } as any)
    const test = getKmsClient(region)
    expect(test).instanceOf(TestKMS)
    expect(assertCount).to.equal(1)
  })

  it('Postcondition: A region must be configured.', () => {
    let assertCount = 0
    const TestKMS: any = class {
      constructor () {
        assertCount++
      }
    }
    const getKmsClient = getClient(TestKMS)
    expect(() => getKmsClient('')).to.throw()
    expect(() => getKmsClient({} as any)).to.throw()
    expect(assertCount).to.equal(2)
  })
})

describe('limitRegions', () => {
  it('return a client', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
        this.config = { region }
      }
    }
    const getKmsClient = getClient(TestKMS)
    const limitKmsClient = limitRegions(['us-west-2'], getKmsClient)
    const test = limitKmsClient(region)
    expect(test).instanceOf(TestKMS)
    expect(assertCount).to.equal(1)
  })

  it('limits by region', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
      }
    }
    const getKmsClient = getClient(TestKMS)
    const limitKmsClient = limitRegions(['us-east-2'], getKmsClient)
    const test = limitKmsClient(region)
    expect(test).to.equal(false)
    expect(assertCount).to.equal(0)
  })

  it('Precondition: region be a string.', () => {
    expect(() => limitRegions(['us-east-2', ''], (() => {}) as any)).to.throw()
    expect(() => limitRegions(['us-east-2', {}] as any, (() => {}) as any)).to.throw()
  })
})

describe('excludeRegions', () => {
  it('exclude client', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
      }
    }
    const getKmsClient = getClient(TestKMS)
    const excludeKmsClient = excludeRegions(['us-west-2'], getKmsClient)
    const test = excludeKmsClient(region)
    expect(test).to.equal(false)
    expect(assertCount).to.equal(0)
  })

  it('return a client', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
        this.config = { region }
      }
    }
    const getKmsClient = getClient(TestKMS)
    const excludeKmsClient = excludeRegions(['us-east-2'], getKmsClient)
    const test = excludeKmsClient(region)
    expect(test).instanceOf(TestKMS)
    expect(assertCount).to.equal(1)
  })

  it('Precondition: region be a string.', () => {
    expect(() => excludeRegions(['us-east-2', ''], (() => {}) as any)).to.throw()
    expect(() => excludeRegions(['us-east-2', {}] as any, (() => {}) as any)).to.throw()
  })
})

describe('cacheClients', () => {
  it('return a client', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
        this.config = { region }
      }
    }
    const getKmsClient = cacheClients(getClient(TestKMS))
    const test = getKmsClient(region)
    expect(test).instanceOf(TestKMS)
    expect(assertCount).to.equal(1)
  })

  it('does not cache the client until KMS has been contacted', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
        this.config = { region }
      }
    }
    const getKmsClient = cacheClients(getClient(TestKMS))
    const test = getKmsClient(region)
    expect(test).instanceOf(TestKMS)
    expect(assertCount).to.equal(1)

    const test2 = getKmsClient(region)
    expect(test === test2).to.equal(false)
    expect(assertCount).to.equal(2)
  })

  it('cache the client after KMS has been contacted', async () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor (config: any) {
        expect(config.region).to.equal(region)
        assertCount++
        this.config = { region }
      }
      async decrypt () {

      }
    }
    const getKmsClient = cacheClients(getClient(TestKMS))
    const test = getKmsClient(region)
    if (!test) throw new Error('never')
    expect(test).instanceOf(TestKMS)
    expect(assertCount).to.equal(1)

    // @ts-ignore
    await test.decrypt({} as any)

    const test2 = getKmsClient(region)
    expect(test === test2).to.equal(true)
    expect(assertCount).to.equal(1)
  })
})
