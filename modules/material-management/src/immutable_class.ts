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

export function immutableClass (ObjectClass: any) {
  Object.freeze(ObjectClass)
  const propertyNames = Object.getOwnPropertyNames(ObjectClass.prototype)
  propertyNames
    .filter(name => name !== 'constructor')
    .forEach(name => Object.defineProperty(ObjectClass.prototype, name, { writable: false }))
  Object.seal(ObjectClass.prototype)
  return ObjectClass
}

export function immutableBaseClass (ObjectClass: any) {
  Object.setPrototypeOf(ObjectClass.prototype, null)
  immutableClass(ObjectClass)
  return ObjectClass
}

export function frozenClass (ObjectClass: any) {
  Object.setPrototypeOf(ObjectClass.prototype, null)
  Object.freeze(ObjectClass.prototype)
  Object.freeze(ObjectClass)
  return ObjectClass
}

export function readOnlyBinaryProperty (obj: any, name: string, value: Uint8Array) {
  // should this also add a zero property?
  // and should it create a local value?  maybe not.
  const safeValue = new Uint8Array(value)
  Object.defineProperty(obj, name, {
    get: () => new Uint8Array(safeValue), // inefficient, but immutable
    enumerable: true
  })
}

export function readOnlyProperty<T, K extends keyof T> (obj: T, name: K, value: T[K]) {
  Object.defineProperty(obj, name, { value, enumerable: true })
}
