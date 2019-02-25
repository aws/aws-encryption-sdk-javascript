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

import { immutableClass, readOnlyProperty } from './immutable_class'
import { Keyring } from './keyring'
import { EncryptionContext, EncryptionMaterial, DecryptionMaterial, SupportedAlgorithmSuites } from './types' // eslint-disable-line no-unused-vars
import { needs } from './needs'
import { EncryptedDataKey } from './encrypted_data_key' // eslint-disable-line no-unused-vars

export class MultiKeyring<S extends SupportedAlgorithmSuites> extends Keyring<S> {
  public readonly generator?: Keyring<S>
  public readonly children!: Keyring<S>[]
  public readonly addChild!: (...children: Keyring<S>[]) => MultiKeyring<S>
  constructor (generator?: Keyring<S>, ..._children: Keyring<S>[]) {
    super()
    /* Precondition: generator must be a Keyring. */
    if (generator && !(generator instanceof Keyring)) throw new Error('')
    const children: Keyring<S>[] = []
    Object.defineProperty(this, 'children', {
      get: () => [...children], // inefficient, but immutable
      enumerable: true
    })
    const addChild = (..._children: Keyring<S>[]) => {
      if (!_children.every(kr => kr instanceof Keyring)) throw new Error('')
      children.push(..._children)
      return this
    }
    readOnlyProperty<MultiKeyring<S>, 'addChild'>(this, 'addChild', addChild)
    readOnlyProperty<MultiKeyring<S>, 'generator'>(this, 'generator', generator)
    this.addChild(..._children)
  }

  async _onEncrypt (material: EncryptionMaterial<S>, context?: EncryptionContext) {
    const generated = this.generator
      ? await this.generator.onEncrypt(material, context)
      : material

    /* Precondition: A Generator Keyring *must* ensure generated material. */
    needs(this.generator && generated.hasUnencryptedDataKey, 'Generator Keyring has not generated material.')
    /* Precondition: Only Keyrings explicitly designated as generators can generate material. */
    needs(generated.hasUnencryptedDataKey, 'Only Keyrings explicitly designated as generators can generate material.')

    /* By default this is a serial operation.  A keyring _may_ perform an expensive operation
     * or create resource constraints such that encrypting with multiple keyrings could
     * fail in unexpected ways.
     * Additionally, "downstream" keyrings may make choices about the EncryptedDataKeys they
     * append based on already appended EDK's.
     */
    for (const keyring of this.children) {
      await keyring.onEncrypt(generated, context)
    }

    // A Postcondition for Keyrings is that they must not create new CryptographicMaterial
    // therefore the generated material has all the data we want
    return generated
  }

  async _onDecrypt (material: DecryptionMaterial<S>, encryptedDataKeys: EncryptedDataKey[], context?: EncryptionContext) {
    const children = this.children
    // children returns a clone, so mutating it will not change the underlying array
    if (this.generator) children.unshift(this.generator)

    for (const keyring of children) {
      try {
        await keyring.onDecrypt(material, encryptedDataKeys, context)
      } catch (e) {
        // there should be some debug here?  or wrap?
        // Failures onDecrypt should not short-circuit the process
        // If the caller does not have access they may have access
        // through another Keyring.
      }

      // Once I have an unencrypted data key do not attempt any more decrypts
      if (material.hasUnencryptedDataKey) return material
    }
    return material
  }
}

immutableClass(MultiKeyring)
