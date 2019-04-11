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

// @ts-ignore
import asn from 'asn1.js'

export const Rfc5915Key = asn.define('Rfc5915Key', function (this: any) {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').optional().explicit(0).objid({
      '1 2 840 10045 3 1 7': 'p256',
      '1 3 132 0 34': 'p384'
    }),
    this.key('publicKey').optional().explicit(1).bitstr()
  )
})
