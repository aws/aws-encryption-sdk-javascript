/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
