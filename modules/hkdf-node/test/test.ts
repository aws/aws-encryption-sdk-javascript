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
import { HKDF } from '../src/index'
import { UnsupportedAlgorithm, KeyLengthError } from '../src/errors'

describe('HKDF', () => {
  it('basic shape', () => {
    expect(typeof HKDF === 'function').to.equal(true)

    const hkdf = HKDF()
    expect(typeof hkdf === 'function').to.equal(true)
    expect(typeof hkdf.expand === 'function').to.equal(true)
    expect(typeof hkdf.extract === 'function').to.equal(true)
  })

  it('throw UnsupportedAlgorithm', () => {
    expect(() => HKDF('not a hash algorithm')).to.throw(UnsupportedAlgorithm)
  })

  it('should be able to expand from a given length and info', () => {
    const expand = HKDF()('some key', 'some salt')
    const expectedKey = Buffer.from('9a7b6b60ce53ce195ee18877c70dbaae2a9a8fca1b53cc82e0f4237fe754cda0', 'hex')
    const key = expand(32, Buffer.from('00b242383932394230313735334434413435', 'hex'))
    expect(key.equals(expectedKey)).to.equal(true)
  })

  it('should be able to expand from a length shorter than hashLength', () => {
    const expand = HKDF('sha256')('some key', 'some salt')
    const expectedKey = Buffer.from('9a7b6b60ce53ce195ee18877c70dba', 'hex')
    const key = expand(15, Buffer.from('00b242383932394230313735334434413435', 'hex'))
    expect(key.equals(expectedKey)).to.equal(true)
  })

  it('should be able to expand with no info', () => {
    const expand = HKDF()('some key', 'some salt')
    const expectedKey = Buffer.from('78fb6516e40671a0df91923c7f283a', 'hex')
    const key = expand(15)
    expect(key.equals(expectedKey)).to.equal(true)
  })

  it('should be able to expand to a length significantly longer than hashLength', () => {
    const expand = HKDF('sha256')('some key', 'some salt')
    const key = expand(32 * 10, Buffer.from('00b242383932394230313735334434413435', 'hex'))
    const expectedKey = Buffer.from(
      [
        'mntrYM5Tzhle4Yh3xw26riqaj8obU8yC4PQjf+dUzaDQicn+rgyNoN1xaG24vLWH40mq8ZW4+bysfQdKW3xBtdAS4',
        'pV8UM2ING05ZDr3M5qifH9AprEaLF3KdSFRqUIp33k2sj3aQE+rquaJn5dOOxrpCAp+oVORsxl4SWbRA4oX1CgIZp',
        'xOquvTjCqkQD6PGA2DtH/iU6xknfp3gNqbHb1Osye6sAMjHBjfvLbYwFkEAodKGAsitZaP06SzOcwxLczyDoa2G1M',
        'wHvyGgSYouXrDZZej+INmv285VzxTJ5OoT7t63FNtzf4qRwKiAQ7OaNM19M7pXkmDLDjlw6Km2U9zpi6sZPdj4Xrj',
        'DjVZdjbQohAy1gUxwrDP0oISAMMqrhp9jYKNos1WYnkU3eG8w0bkdYSHcv6hrECFn8OWY+s='
      ].join(''), 'base64')
    expect(key.equals(expectedKey)).to.equal(true)
  })

  it('expand should throw if we try to expand beyond 255*hashLength', () => {
    const expand = HKDF('sha256')('some key', 'some salt')
    expect(() => expand(32 * 256)).to.throw(KeyLengthError, '8160')
  })
})

describe('https://tools.ietf.org/html/rfc5869#appendix-A', () => {
  it('A.1.  Test Case 1 Basic test case with SHA-256', () => {
    const Hash = 'sha256'
    const IKM = Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex')
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex')
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')
    const L = 42

    const PRK = Buffer.from('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5', 'hex')
    const OKM = Buffer.from('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865', 'hex')

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM, salt)
    expect(PRK.equals(_prk)).to.equal(true)
    const _okm = expand(PRK, L, info)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM, salt)(L, info))).to.equal(true)
  })

  it('A.2.  Test Case 2: Test with SHA-256 and longer inputs/outputs', () => {
    const Hash = 'sha256'
    const IKM = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f', 'hex')
    const salt = Buffer.from('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf', 'hex')
    const info = Buffer.from('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'hex')
    const L = 82

    const PRK = Buffer.from('06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244', 'hex')
    const OKM = Buffer.from('b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87', 'hex')

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM, salt)
    expect(PRK.equals(_prk)).to.equal(true)
    const _okm = expand(PRK, L, info)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM, salt)(L, info))).to.equal(true)
  })

  it('A.3.  Test Case 3: Test with SHA-256 and zero-length salt/info', () => {
    const Hash = 'sha256'
    const IKM = Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex')
    const salt = Buffer.alloc(0)
    const info = Buffer.alloc(0)
    const L = 42

    const PRK = Buffer.from('19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04', 'hex')
    const OKM = Buffer.from('8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8', 'hex')

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM, salt)
    expect(PRK.equals(_prk)).to.equal(true)
    const _okm = expand(PRK, L, info)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM, salt)(L, info))).to.equal(true)
  })

  it('A.4.  Test Case 4: Basic test case with SHA-1', () => {
    const Hash = 'sha1'
    const IKM = Buffer.from('0b0b0b0b0b0b0b0b0b0b0b', 'hex')
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex')
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')
    const L = 42

    const PRK = Buffer.from('9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243', 'hex')
    const OKM = Buffer.from('085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896', 'hex')

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM, salt)
    expect(PRK.equals(_prk)).to.equal(true)
    const _okm = expand(PRK, L, info)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM, salt)(L, info))).to.equal(true)
  })

  it('A.5.  Test Case 5: Test with SHA-1 and longer inputs/outputs', () => {
    const Hash = 'sha1'
    const IKM = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f', 'hex')
    const salt = Buffer.from('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf', 'hex')
    const info = Buffer.from('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', 'hex')
    const L = 82

    const PRK = Buffer.from('8adae09a2a307059478d309b26c4115a224cfaf6', 'hex')
    const OKM = Buffer.from('0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4', 'hex')

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM, salt)
    expect(PRK.equals(_prk)).to.equal(true)
    const _okm = expand(PRK, L, info)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM, salt)(L, info))).to.equal(true)
  })

  it('A.6.  Test Case 6: Test with SHA-1 and zero-length salt/info', () => {
    const Hash = 'sha1'
    const IKM = Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex')
    const salt = Buffer.alloc(0)
    const info = Buffer.alloc(0)
    const L = 42

    const PRK = Buffer.from('da8c8a73c7fa77288ec6f5e7c297786aa0d32d01', 'hex')
    const OKM = Buffer.from('0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918', 'hex')

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM, salt)
    expect(PRK.equals(_prk)).to.equal(true)
    const _okm = expand(PRK, L, info)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM, salt)(L, info))).to.equal(true)
  })

  it('A.7.  Test Case 7: Test with SHA-1, salt not provided (defaults to HashLen zero octets zero-length info),', () => {
    const Hash = 'sha1'
    const IKM = Buffer.from('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', 'hex')
    const salt = false // not provided (defaults to HashLen zero octets)
    const info = Buffer.alloc(0)
    const L = 42

    const PRK = Buffer.from('2adccada18779e7c2077ad2eb19d3f3e731385dd', 'hex')
    const OKM = Buffer.from('2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48', 'hex')

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM, salt)
    expect(PRK.equals(_prk)).to.equal(true)
    const _okm = expand(PRK, L, info)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM, salt)(L, info))).to.equal(true)
  })
})

describe('sha384', () => {
  // See: https://github.com/awslabs/aws-encryption-sdk-c/blob/master/tests/unit/t_hkdf.c#L95
  it('Test with SHA-384 and longer inputs/outputs', () => {
    const Hash = 'sha384'
    const IKM = Buffer.from([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
      0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
      0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
      0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
      0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f])
    const salt = Buffer.from([
      0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
      0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
      0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
      0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
      0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
      0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf ])
    const info = Buffer.from([
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
      0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
      0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
      0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
      0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
      0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff ])

    const OKM = Buffer.from([
      0x48, 0x4c, 0xa0, 0x52, 0xb8, 0xcc, 0x72, 0x4f, 0xd1, 0xc4, 0xec, 0x64,
      0xd5, 0x7b, 0x4e, 0x81, 0x8c, 0x7e, 0x25, 0xa8, 0xe0, 0xf4, 0x56, 0x9e,
      0xd7, 0x2a, 0x6a, 0x05, 0xfe, 0x06, 0x49, 0xee, 0xbf, 0x69, 0xf8, 0xd5,
      0xc8, 0x32, 0x85, 0x6b, 0xf4, 0xe4, 0xfb, 0xc1, 0x79, 0x67, 0xd5, 0x49,
      0x75, 0x32, 0x4a, 0x94, 0x98, 0x7f, 0x7f, 0x41, 0x83, 0x58, 0x17, 0xd8,
      0x99, 0x4f, 0xdb, 0xd6, 0xf4, 0xc0, 0x9c, 0x55, 0x00, 0xdc, 0xa2, 0x4a,
      0x56, 0x22, 0x2f, 0xea, 0x53, 0xd8, 0x96, 0x7a, 0x8b, 0x2e ])

    const L = OKM.byteLength

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM, salt)
    const _okm = expand(_prk, L, info)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM, salt)(L, info))).to.equal(true)
  })

  // See: https://github.com/awslabs/aws-encryption-sdk-c/blob/master/tests/unit/t_hkdf.c#L126
  it('Test with SHA-384 and zero-length salt/info', () => {
    const Hash = 'sha384'
    const IKM = Buffer.from([
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b])

    const OKM = Buffer.from([
      0xc8, 0xc9, 0x6e, 0x71, 0x0f, 0x89, 0xb0, 0xd7, 0x99, 0x0b, 0xca,
      0x68, 0xbc, 0xde, 0xc8, 0xcf, 0x85, 0x40, 0x62, 0xe5, 0x4c, 0x73,
      0xa7, 0xab, 0xc7, 0x43, 0xfa, 0xde, 0x9b, 0x24, 0x2d, 0xaa, 0xcc,
      0x1c, 0xea, 0x56, 0x70, 0x41, 0x5b, 0x52, 0x84, 0x9c ])

    const L = OKM.byteLength

    const hkdf = HKDF(Hash)
    const { extract, expand } = hkdf

    const _prk = extract(IKM)
    const _okm = expand(_prk, L)
    expect(OKM.equals(_okm)).to.equal(true)

    // simple interface still works
    expect(OKM.equals(hkdf(IKM)(L))).to.equal(true)
  })
})
