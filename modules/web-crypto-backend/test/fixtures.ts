// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const fakeWindowWebCryptoSupportsZeroByteGCM: Window = {
  crypto: {
    getRandomValues: () => {},
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

export const fakeWindowIE11OnComplete = {
  msCrypto: {
    getRandomValues: (values: Uint8Array) => {
      return values.fill(1)
    },
    subtle: {
      decrypt() {
        const obj = {} as any
        setTimeout(() => {
          obj.result = true
          obj.oncomplete()
        })
        return obj
      },
      digest() {
        const obj = {} as any
        setTimeout(() => {
          obj.result = true
          obj.oncomplete()
        })
        return obj
      },
      encrypt() {
        const obj = {} as any
        setTimeout(() => {
          obj.result = true
          obj.oncomplete()
        })
        return obj
      },
      exportKey() {
        const obj = {} as any
        setTimeout(() => {
          obj.result = true
          obj.oncomplete()
        })
        return obj
      },
      generateKey() {
        const obj = {} as any
        setTimeout(() => {
          obj.result = true
          obj.oncomplete()
        })
        return obj
      },
      importKey() {
        const obj = {} as any
        setTimeout(() => {
          obj.result = true
          obj.oncomplete()
        })
        return obj
      },
      sign() {
        const obj = {} as any
        setTimeout(() => {
          obj.result = true
          obj.oncomplete()
        })
        return obj
      },
      verify() {
        const obj = {} as any
        setTimeout(() => {
          obj.result = true
          obj.oncomplete()
        })
        return obj
      },
    },
  },
  MSInputMethodContext: {} as any,
} as any

export const fakeWindowIE11OnError = {
  msCrypto: {
    getRandomValues: (values: Uint8Array) => {
      return values.fill(1)
    },
    subtle: {
      decrypt() {
        const obj = {} as any
        setTimeout(() => {
          obj.onerror(new Error('stub error'))
        })
        return obj
      },
      digest() {
        const obj = {} as any
        setTimeout(() => {
          obj.onerror(new Error('stub error'))
        })
        return obj
      },
      encrypt() {
        const obj = {} as any
        setTimeout(() => {
          obj.onerror(new Error('stub error'))
        })
        return obj
      },
      exportKey() {
        const obj = {} as any
        setTimeout(() => {
          obj.onerror(new Error('stub error'))
        })
        return obj
      },
      generateKey() {
        const obj = {} as any
        setTimeout(() => {
          obj.onerror(new Error('stub error'))
        })
        return obj
      },
      importKey() {
        const obj = {} as any
        setTimeout(() => {
          obj.onerror(new Error('stub error'))
        })
        return obj
      },
      sign() {
        const obj = {} as any
        setTimeout(() => {
          obj.onerror(new Error('stub error'))
        })
        return obj
      },
      verify() {
        const obj = {} as any
        setTimeout(() => {
          obj.onerror(new Error('stub error'))
        })
        return obj
      },
    },
  },
  MSInputMethodContext: {} as any,
} as any
