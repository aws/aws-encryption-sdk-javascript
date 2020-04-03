// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { EncryptionRequest, DecryptionRequest } from '.' // eslint-disable-line no-unused-vars
import { EncryptionMaterial, DecryptionMaterial, SupportedAlgorithmSuites } from './types' // eslint-disable-line no-unused-vars
import { NodeAlgorithmSuite } from './node_algorithms' // eslint-disable-line no-unused-vars
import { WebCryptoAlgorithmSuite } from './web_crypto_algorithms' // eslint-disable-line no-unused-vars

/*
 * This public interface to the MaterialsManager object is provided for
 * developers of CMMs and keyrings only. If you are a user of the AWS Encryption
 * SDK and you are not developing your own CMMs and/or keyrings, you do not
 * need to use it and you should not do so.
 */

export interface GetEncryptionMaterials<S extends SupportedAlgorithmSuites> {
  (request: EncryptionRequest<S>): Promise<EncryptionMaterial<S>>
}

export interface GetDecryptMaterials<S extends SupportedAlgorithmSuites> {
  (request: DecryptionRequest<S>): Promise<DecryptionMaterial<S>>
}

export interface MaterialsManager<S extends SupportedAlgorithmSuites> {
  getEncryptionMaterials: GetEncryptionMaterials<S>
  decryptMaterials: GetDecryptMaterials<S>
}

export interface NodeMaterialsManager extends MaterialsManager<NodeAlgorithmSuite> {}
export interface WebCryptoMaterialsManager extends MaterialsManager<WebCryptoAlgorithmSuite> {}
