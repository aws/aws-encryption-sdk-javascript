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
import sinon from 'sinon'
import 'mocha'
import { pluckSubtleCrypto, windowRequiresFallback, webCryptoBackendFactory } from '../src/backend-factory'
import * as browserWindow from '@aws-sdk/util-locate-window'

import * as fixtures from './fixtures'
chai.use(chaiAsPromised)
const { expect } = chai

describe('pluckSubtleCrypto', () => {
  it('return false', () => {
    const test = pluckSubtleCrypto(fixtures.fakeWindowNoWebCrypto)
    expect(test).to.eql(false)
  })

  it('return subtle object', () => {
    const test = pluckSubtleCrypto(fixtures.fakeWindowWebCryptoSupportsZeroByteGCM)
    expect(test === fixtures.fakeWindowWebCryptoSupportsZeroByteGCM.crypto.subtle).to.equal(true)
  })
})

describe('windowRequiresFallback', () => {
  it('returns false', async () => {
    const test = await windowRequiresFallback(fixtures.fakeWindowWebCryptoSupportsZeroByteGCM)
    expect(test).to.eql(false)
  })

  it('returns true', async () => {
    const test = await windowRequiresFallback(fixtures.fakeWindowWebCryptoZeroByteEncryptFail)
    expect(test).to.eql(true)
  })
})

describe('webCryptoBackendFactory', () => {
  describe('configureFallback', () => {
    it('returns a valid and configured fallback.', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowNoWebCrypto)

      const { configureFallback } = webCryptoBackendFactory(fixtures.fakeWindowNoWebCrypto)
      const test = await configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM)

      // @ts-ignore
      browserWindow.locateWindow = locateWindow
      expect(test === fixtures.subtleFallbackSupportsZeroByteGCM).to.equal(true)
    })

    it('Precondition: If a fallback is not required, do not configure one.', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoSupportsZeroByteGCM)

      const { configureFallback } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoSupportsZeroByteGCM)
      const test = await configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM)
      // @ts-ignore
      browserWindow.locateWindow = locateWindow

      expect(test).to.equal(undefined)
    })

    it('Precondition: Can not reconfigure fallback.', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoOnlyRandomSource)

      const { configureFallback } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoOnlyRandomSource)
      await configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM)

      expect(configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM)).to.rejectedWith(Error)

      // @ts-ignore
      browserWindow.locateWindow = locateWindow
    })

    it('Precondition: Fallback must look like it supports the required operations.', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoOnlyRandomSource)

      const { configureFallback } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoOnlyRandomSource)

      expect(configureFallback(fixtures.subtleFallbackNoWebCrypto)).to.rejectedWith(Error)

      // @ts-ignore
      browserWindow.locateWindow = locateWindow
    })

    it('Postcondition: The fallback must specifically support ZeroByteGCM.', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoOnlyRandomSource)

      const { configureFallback } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoOnlyRandomSource)

      expect(configureFallback(fixtures.subtleFallbackZeroByteEncryptFail)).to.rejectedWith(Error)

      // @ts-ignore
      browserWindow.locateWindow = locateWindow
    })
  })

  describe('getWebCryptoBackend', () => {
    it('getWebCryptoBackend returns subtle and randomValues', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoSupportsZeroByteGCM)

      const { getWebCryptoBackend } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoSupportsZeroByteGCM)
      const test = await getWebCryptoBackend()
      // @ts-ignore
      browserWindow.locateWindow = locateWindow

      expect(test).to.have.property('subtle').and.to.eql(fixtures.fakeWindowWebCryptoSupportsZeroByteGCM.crypto.subtle)
      expect(test).to.have.property('randomValues')
    })

    it('Precondition: Access to a secure random source is required.', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowNoWebCrypto)

      const { getWebCryptoBackend } = webCryptoBackendFactory(fixtures.fakeWindowNoWebCrypto)
      await expect(getWebCryptoBackend()).to.rejectedWith(Error)

      // @ts-ignore
      browserWindow.locateWindow = locateWindow
    })

    it('Postcondition: If no SubtleCrypto exists, a fallback must configured.', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoOnlyRandomSource)

      const { getWebCryptoBackend } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoOnlyRandomSource)
      await expect(getWebCryptoBackend()).to.rejectedWith(Error)
      // @ts-ignore
      browserWindow.locateWindow = locateWindow
    })

    it('Postcondition: If a a subtle backend exists and a fallback is required, one must be configured.', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoZeroByteEncryptFail)

      const { getWebCryptoBackend } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoZeroByteEncryptFail)
      await expect(getWebCryptoBackend()).to.rejectedWith(Error)
      // @ts-ignore
      browserWindow.locateWindow = locateWindow
    })

    it('getWebCryptoBackend returns configured fallback subtle and randomValues', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoOnlyRandomSource)

      const { getWebCryptoBackend, configureFallback } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoOnlyRandomSource)
      configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM)
      const test = await getWebCryptoBackend()
      // @ts-ignore
      browserWindow.locateWindow = locateWindow

      expect(test).to.have.property('subtle').and.to.eql(fixtures.subtleFallbackSupportsZeroByteGCM)
      expect(test).to.have.property('randomValues')
    })

    it('getWebCryptoBackend returns MixedSupportWebCryptoBackend', async () => {
      const { locateWindow } = browserWindow
      sinon.stub(browserWindow, 'locateWindow').returns(fixtures.fakeWindowWebCryptoZeroByteEncryptFail)

      const { getWebCryptoBackend, configureFallback } = webCryptoBackendFactory(fixtures.fakeWindowWebCryptoZeroByteEncryptFail)
      configureFallback(fixtures.subtleFallbackSupportsZeroByteGCM)
      const test = await getWebCryptoBackend()
      // @ts-ignore
      browserWindow.locateWindow = locateWindow

      expect(test).to.have.property('nonZeroByteSubtle').and.to.eql(fixtures.fakeWindowWebCryptoZeroByteEncryptFail.crypto.subtle)
      expect(test).to.have.property('zeroByteSubtle').and.to.eql(fixtures.subtleFallbackSupportsZeroByteGCM)
      expect(test).to.have.property('randomValues')
    })
  })
})
