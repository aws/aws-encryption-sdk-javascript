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

import { immutableClass, readOnlyProperty } from './immutable_class'
import {
  Keyring, // eslint-disable-line no-unused-vars
  KeyringNode,
  KeyringWebCrypto
} from './keyring'
import { EncryptionContext, SupportedAlgorithmSuites, EncryptionMaterial, DecryptionMaterial } from './types' // eslint-disable-line no-unused-vars
import { needs } from './needs'
import { EncryptedDataKey } from './encrypted_data_key' // eslint-disable-line no-unused-vars
import { NodeAlgorithmSuite } from './node_algorithms' // eslint-disable-line no-unused-vars
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms' // eslint-disable-line no-unused-vars

export class MultiKeyringNode extends KeyringNode implements IMultiKeyring<NodeAlgorithmSuite> {
  public readonly generator?: KeyringNode
  public readonly children!: ReadonlyArray<KeyringNode>
  constructor (input: MultiKeyringInput<NodeAlgorithmSuite>) {
    super()
    decorateProperties(this, KeyringNode, input)
  }
  _onEncrypt = buildPrivateOnEncrypt<NodeAlgorithmSuite>()
  _onDecrypt = buildPrivateOnDecrypt<NodeAlgorithmSuite>()
}
immutableClass(MultiKeyringNode)

export class MultiKeyringWebCrypto extends KeyringWebCrypto implements IMultiKeyring<WebCryptoAlgorithmSuite> {
  public readonly generator?: KeyringWebCrypto
  public readonly children!: ReadonlyArray<KeyringWebCrypto>

  constructor (input: MultiKeyringInput<WebCryptoAlgorithmSuite>) {
    super()
    decorateProperties(this, KeyringWebCrypto, input)
  }
  _onEncrypt = buildPrivateOnEncrypt<WebCryptoAlgorithmSuite>()
  _onDecrypt = buildPrivateOnDecrypt<WebCryptoAlgorithmSuite>()
}
immutableClass(MultiKeyringWebCrypto)

function decorateProperties<S extends SupportedAlgorithmSuites> (
  obj: IMultiKeyring<S>,
  BaseKeyring: any,
  { generator, children = [] }: MultiKeyringInput<S>
) {
  /* Precondition: MultiKeyring must have keyrings. */
  needs(generator || children.length, 'Noop MultiKeyring is not supported.')
  /* Precondition: generator must be a Keyring. */
  needs(!!generator === generator instanceof BaseKeyring, 'Generator must be a Keyring')
  /* Precondition: All children must be Keyrings. */
  needs(children.every(kr => kr instanceof BaseKeyring), 'Child must be a Keyring')

  readOnlyProperty(obj, 'children', Object.freeze(children.slice()))
  readOnlyProperty(obj, 'generator', generator)
}

function buildPrivateOnEncrypt<S extends SupportedAlgorithmSuites> () {
  return async function _onEncrypt (
    this: IMultiKeyring<S>,
    material: EncryptionMaterial<S>, context?: EncryptionContext
  ): Promise<EncryptionMaterial<S>> {
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

    // Keyrings are required to not create new EncryptionMaterial instances, but
    // only append EncryptedDataKey.  Therefore the generated material has all
    // the data I want.
    return generated
  }
}

function buildPrivateOnDecrypt<S extends SupportedAlgorithmSuites> () {
  return async function _onDecrypt (
    this: IMultiKeyring<S>,
    material: DecryptionMaterial<S>,
    encryptedDataKeys: EncryptedDataKey[],
    context?: EncryptionContext
  ): Promise<DecryptionMaterial<S>> {
    const children = this.children.slice()
    if (this.generator) children.unshift(this.generator)

    for (const keyring of children) {
    /* Check for early return (Postcondition): Do not attempt to decrypt once I have a valid key. */
      if (material.hasValidKey()) return material

      try {
        await keyring.onDecrypt(material, encryptedDataKeys, context)
      } catch (e) {
      // there should be some debug here?  or wrap?
      // Failures onDecrypt should not short-circuit the process
      // If the caller does not have access they may have access
      // through another Keyring.
      }
    }
    return material
  }
}

interface MultiKeyringInput<S extends SupportedAlgorithmSuites> {
  generator?: Keyring<S>
  children?: Keyring<S>[]
}

interface IMultiKeyring<S extends SupportedAlgorithmSuites> extends Keyring<S> {
  generator?: Keyring<S>
  children: ReadonlyArray<Keyring<S>>
}
