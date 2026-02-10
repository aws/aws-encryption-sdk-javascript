// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const fakeWindowWebCryptoSupportsZeroByteGCM: Window = {
  crypto: {
    getRandomValues: (array: Uint8Array) => {
      for (let i = 0; i < array.length; i++) {
        array[i] = Math.floor(Math.random() * 256)
      }
      return array
    },
    subtle: {
      async decrypt() {
        return {} as any
      },
      async digest() {
        return {} as any
      },
      async encrypt() {
        // Mock a valid default tagLength
        // so we support zero byte encryption...
        return { byteLength: 16 } as any
      },
      async exportKey() {
        return {} as any
      },
      async generateKey() {
        return {} as any
      },
      async importKey() {
        return {} as any
      },
      async sign() {
        return {} as any
      },
      async verify() {
        return {} as any
      },
    },
  },
} as any

export const fakeWindowWebCryptoZeroByteEncryptFail: Window = {
  crypto: {
    getRandomValues: () => {},
    subtle: {
      async decrypt() {
        return {} as any
      },
      async digest() {
        return {} as any
      },
      async encrypt(...args: any[]) {
        const [, , data] = args
        if (data.byteLength === 0) {
          throw new Error('Does not support')
        } else {
          return {} as any
        }
      },
      async exportKey() {
        return {} as any
      },
      async generateKey() {
        return {} as any
      },
      async importKey() {
        return {} as any
      },
      async sign() {
        return {} as any
      },
      async verify() {
        return {} as any
      },
    },
  },
} as any

export const fakeWindowWebCryptoOnlyRandomSource: Window = {
  crypto: {
    getRandomValues: () => {},
  },
} as any

export const fakeWindowNoWebCrypto: Window = {} as any

export const subtleFallbackSupportsZeroByteGCM = {
  async decrypt() {
    return {} as any
  },
  async digest() {
    return {} as any
  },
  async encrypt() {
    // Mock a valid default tagLength
    // so we support zero byte encryption...
    return { byteLength: 16 } as any
  },
  async exportKey() {
    return {} as any
  },
  async generateKey() {
    return {} as any
  },
  async importKey() {
    return {} as any
  },
  async sign() {
    return {} as any
  },
  async verify() {
    return {} as any
  },
} as any

export const subtleFallbackZeroByteEncryptFail = {
  async decrypt() {
    return {} as any
  },
  async digest() {
    return {} as any
  },
  async encrypt(...args: any[]) {
    const [, , data] = args
    if (data.byteLength === 0) {
      throw new Error('Does not support')
    } else {
      return {} as any
    }
  },
  async exportKey() {
    return {} as any
  },
  async generateKey() {
    return {} as any
  },
  async importKey() {
    return {} as any
  },
  async sign() {
    return {} as any
  },
  async verify() {
    return {} as any
  },
} as any

export const subtleFallbackNoWebCrypto = {} as any
