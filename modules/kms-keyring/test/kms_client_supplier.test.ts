// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import {
  getClient,
  limitRegions,
  excludeRegions,
  cacheClients,
  deferCache,
} from '../src/kms_client_supplier'

describe('getClient', () => {
  it('return a client', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor(config: any) {
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
      constructor(config: any) {
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
      constructor(config: any) {
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
      constructor() {
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
      constructor(config: any) {
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
      constructor(config: any) {
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

  it('Precondition: limitRegions requires that region be a string.', () => {
    expect(() => limitRegions(['us-east-2', ''], (() => {}) as any)).to.throw()
    expect(() =>
      limitRegions(['us-east-2', {}] as any, (() => {}) as any)
    ).to.throw()
  })
})

describe('excludeRegions', () => {
  it('exclude client', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      constructor(config: any) {
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
      constructor(config: any) {
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

  it('Precondition: excludeRegions requires region be a string.', () => {
    expect(() =>
      excludeRegions(['us-east-2', ''], (() => {}) as any)
    ).to.throw()
    expect(() =>
      excludeRegions(['us-east-2', {}] as any, (() => {}) as any)
    ).to.throw()
  })
})

describe('cacheClients', () => {
  it('return a client', () => {
    const region = 'us-west-2'
    let assertCount = 0
    const TestKMS: any = class {
      config: any
      constructor(config: any) {
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
      constructor(config: any) {
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
      constructor(config: any) {
        expect(config.region).to.equal(region)
        assertCount++
        this.config = { region }
      }
      async decrypt() {}
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

describe('deferCache', () => {
  const noop = async () => ({})
  const client: any = {
    encrypt: noop,
    decrypt: noop,
    generateDataKey: noop,
  }
  const clientsCache: any = {}
  const region = 'region'
  it('modifies the original instance', async () => {
    const wrappedClient = deferCache(clientsCache, region, client)
    expect(wrappedClient === client).to.equal(true)
    expect(client).to.haveOwnProperty('encrypt').and.to.not.equal(noop)
    expect(client).to.haveOwnProperty('decrypt').and.to.not.equal(noop)
    expect(client).to.haveOwnProperty('generateDataKey').and.to.not.equal(noop)
    expect(clientsCache).to.not.haveOwnProperty(region)
  })

  it('resets the functions and caches the client', async () => {
    // Each of the 3 functions are the same cache functions...
    await client.decrypt()

    expect(client).to.haveOwnProperty('encrypt').and.to.equal(noop)
    expect(client).to.haveOwnProperty('decrypt').and.to.equal(noop)
    expect(client).to.haveOwnProperty('generateDataKey').and.to.equal(noop)
    expect(clientsCache).to.haveOwnProperty(region).and.to.equal(client)
  })

  it('Check for early return (Postcondition): No client, then I cache false and move on.', async () => {
    const noClientRegion = 'noClientRegion'
    const wrappedClient = deferCache(clientsCache, noClientRegion, false)
    expect(wrappedClient).to.equal(false)
    expect(clientsCache).to.haveOwnProperty(noClientRegion).and.to.equal(false)
  })
})
