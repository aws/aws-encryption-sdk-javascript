// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { MsSubtleCrypto } from '@aws-crypto/ie11-detection' // eslint-disable-line no-unused-vars

type MsSubtleFunctions = keyof MsSubtleCrypto

export default function promisifyMsSubtleCrypto (backend: MsSubtleCrypto) {
  const usages : MsSubtleFunctions[] = ['decrypt', 'digest', 'encrypt', 'exportKey', 'generateKey', 'importKey', 'sign', 'verify']
  const decorateUsage = (fakeBackend: any, usage: MsSubtleFunctions) => decorate(backend, fakeBackend, usage)
  return <SubtleCrypto>usages.reduce(decorateUsage, {})
}

function decorate (subtle: MsSubtleCrypto, fakeBackend: any, name: MsSubtleFunctions) {
  fakeBackend[name] = (...args:any[]) => {
    return new Promise((resolve, reject) => {
      // @ts-ignore
      const operation = subtle[name](...args)
      operation.oncomplete = () => resolve(operation.result)
      operation.onerror = reject
    })
  }
  return fakeBackend
}
