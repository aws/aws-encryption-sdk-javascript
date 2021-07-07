// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import * as chai from 'chai'
import chaiAsPromised from 'chai-as-promised'
// import 'mocha'
import {
  pluckSubtleCrypto,
  windowRequiresFallback,
  webCryptoBackendFactory,
  getNonZeroByteBackend,
  getZeroByteSubtle,
} from '../src/backend-factory'

import * as fixtures from './fixtures'
chai.use(chaiAsPromised)
const { expect } = chai

describe('pluckSubtleCrypto', () => {
  it('return false', () => {
    const test = pluckSubtleCrypto(fixtures.fakeWindowNoWebCrypto)
    expect(test).to.eql(false)
  })

  it('return subtle object', () => {
    const test = pluckSubtleCrypto(
      fixtures.fakeWindowWebCryptoSupportsZeroByteGCM
    )
    expect(
      test === fixtures.fakeWindowWebCryptoSupportsZeroByteGCM.crypto.subtle
    ).to.equal(true)
  })
})

describe('windowRequiresFallback', () => {
  it('returns false', async () => {
    const test = await windowRequiresFallback(
      fixtures.fakeWindowWebCryptoSupportsZeroByteGCM
    )
    expect(test).to.eql(false)
  })

  it('returns true', async () => {
    const test = await windowRequiresFallback(
      fixtures.fakeWindowWebCryptoZeroByteEncryptFail
    )
    expect(test).to.eql(true)
  })
})

describe('webCryptoBackendFactory', () => {
  describe('configureFallback', () => {
    it('returns a valid and configured fallback.', async () => {
      const { configureFallback } = webCryptoBackendFactory(
        fixtures.fakeWindowNoWebCrypto
      )
      const test = await configureFallback(
        fixtures.subtleFallbackSupportsZeroByteGCM
      )

      expect(test === fixtures.subtleFallbackSupportsZeroByteGCM).to.equal(true)
    })

    it('Precondition: If a fallback is not required, do not configure one.', async () => {
      const { configureFallback } = webCryptoBackendFactory(
        fixtures.fakeWindowWebCryptoSupportsZeroByteGCM
      )
      const test = await configureFallback(
        fixtures.subtleFallbackSupportsZeroByteGCM
      )

      expect(test).to.equal(undefined)
    })

    it('Precondition: Can not reconfigure fallback.', async () => {
      const { configureFallback } = webCryptoBackendFactory(
        fixtures.fakeWindowWebCryptoOnlyRandomSource
      )
      await configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM)

      await expect(
        configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM)
      ).to.rejectedWith(Error)
    })

    it('Precondition: Fallback must look like it supports the required operations.', async () => {
      const { configureFallback } = webCryptoBackendFactory(
        fixtures.fakeWindowWebCryptoOnlyRandomSource
      )

      await expect(
        configureFallback(fixtures.subtleFallbackNoWebCrypto)
      ).to.rejectedWith(Error)
    })

    it('Postcondition: The fallback must specifically support ZeroByteGCM.', async () => {
      const { configureFallback } = webCryptoBackendFactory(
        fixtures.fakeWindowWebCryptoOnlyRandomSource
      )

      await expect(
        configureFallback(fixtures.subtleFallbackZeroByteEncryptFail)
      ).to.rejectedWith(Error)
    })
  })

  describe('getWebCryptoBackend', () => {
    it('getWebCryptoBackend returns subtle and randomValues', async () => {
      const { getWebCryptoBackend } = webCryptoBackendFactory(
        fixtures.fakeWindowWebCryptoSupportsZeroByteGCM
      )
      const test = await getWebCryptoBackend()

      expect(test)
        .to.have.property('subtle')
        .and.to.eql(
          fixtures.fakeWindowWebCryptoSupportsZeroByteGCM.crypto.subtle
        )
      expect(test).to.have.property('randomValues')
    })

    it('Precondition: Access to a secure random source is required.', async () => {
      const { getWebCryptoBackend } = webCryptoBackendFactory(
        fixtures.fakeWindowNoWebCrypto
      )
      await expect(getWebCryptoBackend()).to.rejectedWith(Error)
    })

    it('Postcondition: If no SubtleCrypto exists, a fallback must configured.', async () => {
      const { getWebCryptoBackend } = webCryptoBackendFactory(
        fixtures.fakeWindowWebCryptoOnlyRandomSource
      )
      await expect(getWebCryptoBackend()).to.rejectedWith(Error)
    })

    it('Postcondition: If a a subtle backend exists and a fallback is required, one must be configured.', async () => {
      const { getWebCryptoBackend } = webCryptoBackendFactory(
        fixtures.fakeWindowWebCryptoZeroByteEncryptFail
      )
      await expect(getWebCryptoBackend()).to.rejectedWith(Error)
    })

    it('getWebCryptoBackend returns configured fallback subtle and randomValues', async () => {
      const { getWebCryptoBackend, configureFallback } =
        webCryptoBackendFactory(fixtures.fakeWindowWebCryptoOnlyRandomSource)
      // This is intentionally frustrating.
      // By not waiting for the config,
      // I _also_ test its ability to await the configuration.
      configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM) // eslint-disable-line @typescript-eslint/no-floating-promises
      const test = await getWebCryptoBackend()

      expect(test)
        .to.have.property('subtle')
        .and.to.eql(fixtures.subtleFallbackSupportsZeroByteGCM)
      expect(test).to.have.property('randomValues')
    })

    it('getWebCryptoBackend returns MixedSupportWebCryptoBackend', async () => {
      const { getWebCryptoBackend, configureFallback } =
        webCryptoBackendFactory(fixtures.fakeWindowWebCryptoZeroByteEncryptFail)
      // This is intentionally frustrating.
      // By not waiting for the config,
      // I _also_ test its ability to await the configuration.
      configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM) // eslint-disable-line @typescript-eslint/no-floating-promises
      const test = await getWebCryptoBackend()

      expect(test)
        .to.have.property('nonZeroByteSubtle')
        .and.to.eql(
          fixtures.fakeWindowWebCryptoZeroByteEncryptFail.crypto.subtle
        )
      expect(test)
        .to.have.property('zeroByteSubtle')
        .and.to.eql(fixtures.subtleFallbackSupportsZeroByteGCM)
      expect(test).to.have.property('randomValues')
    })
  })
})

describe('getNonZeroByteBackend', () => {
  it('gets a subtle backend', () => {
    const test = getNonZeroByteBackend(
      fixtures.subtleFallbackSupportsZeroByteGCM
    )
    expect(test === fixtures.subtleFallbackSupportsZeroByteGCM.subtle).to.equal(
      true
    )
  })

  it('Precondition: A backend must be passed to get a non zero byte backend.', () => {
    expect(() => getNonZeroByteBackend(false)).to.throw('No supported backend.')
  })
})

describe('getZeroByteSubtle', () => {
  it('gets a subtle backend', () => {
    const test = getZeroByteSubtle(fixtures.subtleFallbackSupportsZeroByteGCM)
    expect(test === fixtures.subtleFallbackSupportsZeroByteGCM.subtle).to.equal(
      true
    )
  })

  it('Precondition: A backend must be passed to get a zero byte backend.', () => {
    expect(() => getZeroByteSubtle(false)).to.throw('No supported backend.')
  })
})
