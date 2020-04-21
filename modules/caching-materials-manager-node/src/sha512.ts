// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'crypto'

export const sha512 = async (...data: (Uint8Array | string)[]) =>
  data
    .map((item) => (typeof item === 'string' ? Buffer.from(item) : item))
    .reduce((hash, item) => hash.update(item), createHash('sha512'))
    .digest()
