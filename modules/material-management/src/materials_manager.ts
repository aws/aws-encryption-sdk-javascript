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

import {AlgorithmSuite} from './algorithm_suites'
import {Keyring, EncryptionRequest, DecryptionRequest} from '.'
import {EncryptionMaterial, DecryptionMaterial} from './types'
import {NodeEncryptionMaterial, NodeDecryptionMaterial} from './cryptographic_material'
import {NodeAlgorithmSuite} from './node_algorithms'
import {WebCryptoEncryptionMaterial, WebCryptoDecryptionMaterial} from './cryptographic_material'
import {WebCryptoAlgorithmSuite} from './web_crypto_algorithms'

/*
 * This public interface to the MaterialsManager object is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */

interface MaterialsManager<E extends EncryptionMaterial, D extends DecryptionMaterial, S extends AlgorithmSuite> {
  readonly keyring: Keyring<E, D, S>
  getEncryptionMaterials(request: EncryptionRequest<S>): Promise<E>
  decryptMaterials(request: DecryptionRequest<S>): Promise<D>
}

export interface NodeMaterialsManager extends MaterialsManager<NodeEncryptionMaterial, NodeDecryptionMaterial, NodeAlgorithmSuite> {}
export interface WebCryptoMaterialsManager extends MaterialsManager<WebCryptoEncryptionMaterial, WebCryptoDecryptionMaterial, WebCryptoAlgorithmSuite> {}
