// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SignaturePolicy,
  ClientOptions,
} from '@aws-crypto/material-management-node'

export interface DecryptStreamOptions {
  maxBodySize?: number
}

export interface DecryptParameters {
  signaturePolicy: SignaturePolicy
  clientOptions: ClientOptions
}
