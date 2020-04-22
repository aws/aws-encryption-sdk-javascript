// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export function immutableClass(ObjectClass: any) {
  Object.freeze(ObjectClass)
  const propertyNames = Object.getOwnPropertyNames(ObjectClass.prototype)
  propertyNames
    .filter((name) => name !== 'constructor')
    .forEach((name) =>
      Object.defineProperty(ObjectClass.prototype, name, { writable: false })
    )
  Object.seal(ObjectClass.prototype)
  return ObjectClass
}

export function immutableBaseClass(ObjectClass: any) {
  Object.setPrototypeOf(ObjectClass.prototype, null)
  immutableClass(ObjectClass)
  return ObjectClass
}

export function frozenClass(ObjectClass: any) {
  Object.setPrototypeOf(ObjectClass.prototype, null)
  Object.freeze(ObjectClass.prototype)
  Object.freeze(ObjectClass)
  return ObjectClass
}

export function readOnlyBinaryProperty(
  obj: any,
  name: string,
  value: Uint8Array
) {
  // should this also add a zero property?
  // and should it create a local value?  maybe not.
  const safeValue = new Uint8Array(value)
  Object.defineProperty(obj, name, {
    get: () => new Uint8Array(safeValue), // inefficient, but immutable
    enumerable: true,
  })
}

export function readOnlyProperty<T, K extends keyof T>(
  obj: T,
  name: K,
  value: T[K]
) {
  Object.defineProperty(obj, name, { value, enumerable: true })
}
