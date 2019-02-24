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

import {immutableClass, readOnlyProperty} from './immutable_class'
import {Keyring} from './keyring'
import {DecryptionRequest, EncryptionContext, EncryptionMaterial, DecryptionMaterial} from './types'
import {AlgorithmSuite} from './algorithm_suites'
import { isDecryptionMaterial } from './cryptographic_material';

export class MultiKeyring<E extends EncryptionMaterial, D extends DecryptionMaterial, S extends AlgorithmSuite> extends Keyring<E, D, S> {
  public readonly generator?: Keyring<E, D, S>
  public readonly children!: Keyring<E, D, S>[]
  public readonly addChild!: (...children: Keyring<E, D, S>[]) => MultiKeyring<E, D, S>
  constructor(generator?: Keyring<E, D, S>, ..._children: Keyring<E, D, S>[]) {
    super()
    /* Precondition: generator must be a Keyring. */
    if (generator && !(generator instanceof Keyring)) throw new Error('')
    const children: Keyring<E, D, S>[] = []
    Object.defineProperty(this, 'children', {
      get: () => [...children], // inefficient, but immutable
      enumerable: true,
    })
    const addChild = (..._children: Keyring<E, D, S>[]) => {
      if (!_children.every(kr => kr instanceof Keyring)) throw new Error('')
      children.push(..._children)
      return this
    }
    readOnlyProperty<MultiKeyring<E, D, S>, 'addChild'>(this, 'addChild', addChild)
    readOnlyProperty<MultiKeyring<E, D, S>, 'generator'>(this, 'generator', generator)
    this.addChild(..._children)
  }

  async _onEncrypt(material: E, context?: EncryptionContext) {
    const generated = this.generator
      ? await this.generator.onEncrypt(material, context)
      : material

      /* Precondition: A Generator Keyring *must* insure generated material. */
      if (this.generator && !generated.hasUnencryptedDataKey) {
        /* If we are here, it means we are in one of two possible error cases:
        *
        * (1) This multi-keyring has a generator that did not generate material. Keyrings are not
        *     required to generate a material when it is not provided, but generator keyrings are.
        *
        * (2) This multi-keyring did not have a generator assigned and it was called as the first or
        *     only keyring for encryption.
        */
        throw new Error('')
      }

    // This does the encryption in parallel
    await Promise.all(this.children.map(child => child.onEncrypt(generated, context)))
    // A Postcondition for Keyrings is that they must not create new CryptographicMaterial
    // therefore the generated material has all the data we want
    return generated
  }

  async _onDecrypt(request: DecryptionRequest<S>) {
    const children = this.children
    // children returns a clone, so mutating it will not change the underlying array
    if (this.generator) children.unshift(this.generator)

    for (const keyring of children) {
      let material: Readonly<D|void>
      try {
        material =  await keyring.onDecrypt(request)
      } catch (e) {
        // there should be some debug here?  or wrap?
        // Failures onDecrypt should not short-circuit the process
        // If the caller does not have access they may have access
        // through another Keyring.
      }
      /* Postcondition: If material is returned it must be DecryptionMaterial. 
       * Given keyring.ts this should be impossible.
       */
      if (material && !isDecryptionMaterial(material)) throw Error('')

      // Once we have CryptographicMaterial, there is no need to attempt
      // to call anymore keyrings
      if (material && material.hasUnencryptedDataKey) return material
    }
    return
  }
}

immutableClass(MultiKeyring)
