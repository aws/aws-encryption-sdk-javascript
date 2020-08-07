// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { immutableClass, readOnlyProperty } from './immutable_class'
import { Keyring, KeyringNode, KeyringWebCrypto } from './keyring'
import {
  SupportedAlgorithmSuites,
  EncryptionMaterial,
  DecryptionMaterial,
} from './types'
import { needs } from './needs'
import { EncryptedDataKey } from './encrypted_data_key'
import { NodeAlgorithmSuite } from './node_algorithms'
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms'

export class MultiKeyringNode extends KeyringNode
  implements MultiKeyring<NodeAlgorithmSuite> {
  public readonly generator?: KeyringNode
  public readonly children!: ReadonlyArray<KeyringNode>
  constructor(input: MultiKeyringInput<NodeAlgorithmSuite>) {
    super()
    decorateProperties(this, KeyringNode, input)
  }
  _onEncrypt = buildPrivateOnEncrypt<NodeAlgorithmSuite>()
  _onDecrypt = buildPrivateOnDecrypt<NodeAlgorithmSuite>()
}
immutableClass(MultiKeyringNode)

export class MultiKeyringWebCrypto extends KeyringWebCrypto
  implements MultiKeyring<WebCryptoAlgorithmSuite> {
  public readonly generator?: KeyringWebCrypto
  public readonly children!: ReadonlyArray<KeyringWebCrypto>

  constructor(input: MultiKeyringInput<WebCryptoAlgorithmSuite>) {
    super()
    decorateProperties(this, KeyringWebCrypto, input)
  }
  _onEncrypt = buildPrivateOnEncrypt<WebCryptoAlgorithmSuite>()
  _onDecrypt = buildPrivateOnDecrypt<WebCryptoAlgorithmSuite>()
}
immutableClass(MultiKeyringWebCrypto)

function decorateProperties<S extends SupportedAlgorithmSuites>(
  obj: MultiKeyring<S>,
  BaseKeyring: any,
  { generator, children = [] }: MultiKeyringInput<S>
) {
  /* Precondition: MultiKeyring must have keyrings. */
  needs(generator || children.length, 'Noop MultiKeyring is not supported.')
  /* Precondition: generator must be a Keyring. */
  needs(
    !!generator === generator instanceof BaseKeyring,
    'Generator must be a Keyring'
  )
  /* Precondition: All children must be Keyrings. */
  needs(
    children.every((kr) => kr instanceof BaseKeyring),
    'Child must be a Keyring'
  )

  readOnlyProperty(obj, 'children', Object.freeze(children.slice()))
  readOnlyProperty(obj, 'generator', generator)
}

function buildPrivateOnEncrypt<S extends SupportedAlgorithmSuites>() {
  return async function _onEncrypt(
    this: MultiKeyring<S>,
    material: EncryptionMaterial<S>
  ): Promise<EncryptionMaterial<S>> {
    if (this.generator) {
      /* Precondition: Keyrings designated as generators *must* generate material. */
      needs(!material.hasUnencryptedDataKey, 'Data key already generated.')

      await this.generator.onEncrypt(material)

      /* Precondition: A Generator Keyring *must* generated material. */
      needs(
        material.hasUnencryptedDataKey,
        'Generator keyring did not generated material.'
      )
    } else {
      /* Precondition: Keyrings not designated as generators *must not* generate material. */
      needs(
        material.hasUnencryptedDataKey,
        'No data key provided and no generator defined.'
      )
    }

    /* By default this is a serial operation.  A keyring _may_ perform an expensive operation
     * or create resource constraints such that encrypting with multiple keyrings could
     * fail in unexpected ways.
     * Additionally, "downstream" keyrings may make choices about the EncryptedDataKeys they
     * append based on already appended EDK's.
     */
    for (const keyring of this.children) {
      await keyring.onEncrypt(material)
    }

    // Keyrings are required to not create new EncryptionMaterial instances, but
    // only append EncryptedDataKey.  Therefore the generated material has all
    // the data I want.
    return material
  }
}

function buildPrivateOnDecrypt<S extends SupportedAlgorithmSuites>() {
  return async function _onDecrypt(
    this: MultiKeyring<S>,
    material: DecryptionMaterial<S>,
    encryptedDataKeys: EncryptedDataKey[]
  ): Promise<DecryptionMaterial<S>> {
    const children = this.children.slice()
    if (this.generator) children.unshift(this.generator)

    const childKeyringErrors: Error[] = []

    for (const keyring of children) {
      /* Check for early return (Postcondition): Do not attempt to decrypt once I have a valid key. */
      if (material.hasValidKey()) return material

      try {
        await keyring.onDecrypt(material, encryptedDataKeys)
      } catch (e) {
        /* Failures onDecrypt should not short-circuit the process
         * If the caller does not have access they may have access
         * through another Keyring.
         */
        childKeyringErrors.push(e)
      }
    }

    /* Postcondition: A child keyring must provide a valid data key or no child keyring must have raised an error.
     * If I have a data key,
     * decrypt errors can be ignored.
     * However, if I was unable to decrypt a data key AND I have errors,
     * these errors should bubble up.
     * Otherwise, the only error customers will see is that
     * the material does not have an unencrypted data key.
     * So I return a concatenated Error message
     */
    needs(
      material.hasValidKey() ||
        (!material.hasValidKey() && !childKeyringErrors.length),
      childKeyringErrors.reduce(
        (m, e, i) => `${m} Error #${i + 1} \n ${e.stack} \n`,
        'Unable to decrypt data key and one or more child keyrings had an error. \n '
      )
    )

    return material
  }
}

interface MultiKeyringInput<S extends SupportedAlgorithmSuites> {
  generator?: Keyring<S>
  children?: Keyring<S>[]
}

interface MultiKeyring<S extends SupportedAlgorithmSuites> extends Keyring<S> {
  generator?: Keyring<S>
  children: ReadonlyArray<Keyring<S>>
}
