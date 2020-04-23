// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* eslint-env mocha */

import { expect } from 'chai'
import { publicKeyPem, privateKeyPem, chunk64 } from '../src/pem_helpers'

describe('chunk64', () => {
  it('returns a base64 array of strings', () => {
    const buff = Buffer.alloc(12)
    const test = chunk64(buff)
    expect(test).to.be.an('array').and.to.have.lengthOf(1)
    expect(test[0]).to.equal('AAAAAAAAAAAAAAAA')
  })

  /* Each Base64 digit represents exactly 6 bits of data,
   * so to get 64 characters I need 48 Bytes:
   * 64 characters = 64*6 bits of data == 384
   * 384 bits of data === 384/8 === 48 Bytes
   *
   * See: https://tools.ietf.org/html/rfc4648#section-4
   * Each 6-bit group is used as an index into an array of 64 printable
   * characters.  The character referenced by the index is placed in the
   * output string.
   */
  it('returns a single line', () => {
    const buff = Buffer.alloc(48)
    const test = chunk64(buff)
    expect(test).to.be.an('array').and.to.have.lengthOf(1)
    expect(test[0]).to.equal(
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    )
  })

  it('returns a new line at the demarcation', () => {
    const buff = Buffer.alloc(49)
    const test = chunk64(buff)
    expect(test).to.be.an('array').and.to.have.lengthOf(2)
    expect(test[0]).to.equal(
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    )
    expect(test[1]).to.equal('AA==')
  })

  it('returns a new line at the second demarcation', () => {
    const buff = Buffer.alloc(97)
    const test = chunk64(buff)
    expect(test).to.be.an('array').and.to.have.lengthOf(3)
    expect(test[0]).to.equal(
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    )
    expect(test[1]).to.equal(
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    )
    expect(test[2]).to.equal('AA==')
  })
})

const publicPEM =
  '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuJDriNevbNaMlxogs2hWo4e581BE\nvFOH3ZE6E7EvM2On0+zDd8RGsyg66E6sYNZZYe7lPg/tEz6ZDy0H4dwPaA==\n-----END PUBLIC KEY-----\n'
const privatePEM =
  '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIAKqZVbQgpM90q+mGBGwi6TWnWrH39Dv386uH421mPfqoAoGCCqGSM49\nAwEHoUQDQgAEuJDriNevbNaMlxogs2hWo4e581BEvFOH3ZE6E7EvM2On0+zDd8RG\nsyg66E6sYNZZYe7lPg/tEz6ZDy0H4dwPaA==\n-----END EC PRIVATE KEY-----\n'
const curve = 'prime256v1'
const publicKeyBytes = Buffer.from(
  '04B890EB88D7AF6CD68C971A20B36856A387B9F35044BC5387DD913A13B12F3363A7D3ECC377C446B3283AE84EAC60D65961EEE53E0FED133E990F2D07E1DC0F68',
  'hex'
)
const privateKeyBytes = Buffer.from(
  '02AA6556D082933DD2AFA61811B08BA4D69D6AC7DFD0EFDFCEAE1F8DB598F7EA',
  'hex'
)

describe('pem formating', () => {
  it('convert public key bytes to PEM', () => {
    const pem = publicKeyPem(curve, publicKeyBytes)
    expect(pem).to.equal(publicPEM)
  })

  it('convert private and public key bytes to PME', () => {
    const pem = privateKeyPem(curve, privateKeyBytes, publicKeyBytes)
    expect(pem).to.equal(privatePEM)
  })
})
