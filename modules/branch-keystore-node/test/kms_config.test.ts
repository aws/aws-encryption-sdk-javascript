// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { expect } from 'chai'
import { KmsKeyConfig, RegionalKmsConfig, KmsConfig } from '../src/kms_config'

function supplySrkKmsConfig(config: KmsConfig): KmsKeyConfig {
  return new KmsKeyConfig(config)
}

// causes parseAwsKmsKeyArn to return false
export const ONE_PART_ARN = 'mrk-12345678123412341234123456789012'
// causes parseAwsKmsKeyArn to throw an error
export const MALFORMED_ARN =
  'arn:aws:kms:us-west-2:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'
export const WELL_FORMED_SRK_ARN =
  'arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126'
export const WELL_FORMED_MRK_ARN =
  'arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
export const WELL_FORMED_MRK_ARN_DIFFERENT_REGION =
  'arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7'
export const WELL_FORMED_SRK_ALIAS_ARN =
  'arn:aws:kms:us-west-2:123456789012:alias/srk/my-srk-alias'
export const WELL_FORMED_MRK_ALIAS_ARN =
  'arn:aws:kms:us-west-2:123456789012:alias/mrk/my-mrk-alias'

describe('Test KmsKeyConfig class', () => {

  it('Precondition: config must be a string or object', () => {
    for (const config of [null, undefined, 0]) {
      expect(() => supplySrkKmsConfig(config as any)).to.throw(
        'Config must be a `discovery` or an object.'
      )
    }
  })
  it('Precondition: ARN must be a string', () => {
    for (const arn of [null, undefined, 0, {}]) {
      expect(() => supplySrkKmsConfig({identifier: arn} as any)).to.throw(
        'ARN must be a string'
      )
      expect(() => supplySrkKmsConfig({mrkIdentifier: arn} as any)).to.throw(
        'ARN must be a string'
      )
    }
  })

  describe('Given a well formed SRK arn', () => {
    //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
    //= type=test
    //# `KMS Key ARN` and `KMS MRKey ARN` MUST take an additional argument
    //# that is a KMS ARN.
    const config = supplySrkKmsConfig({ identifier: WELL_FORMED_SRK_ARN })

    it('Test getRegion', () => {
      expect(config.getRegion()).equals('us-west-2')
    })

    //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-key-arn-compatibility
    //= type=test
    //# For two ARNs to be compatible:
    //#
    //# If the [AWS KMS Configuration](#aws-kms-configuration) designates single region ARN compatibility,
    //# then two ARNs are compatible if they are exactly equal.
    describe('Test isCompatibleWithArn', () => {
      it('Given an equal arn', () => {
        expect(config.isCompatibleWithArn(WELL_FORMED_SRK_ARN)).equals(true)
      })

      it('Given a non-equal arn', () => {
        expect(config.isCompatibleWithArn(WELL_FORMED_SRK_ALIAS_ARN)).equals(
          false
        )
      })
    })

    describe('Test getCompatibleArnArn', () => {
      it('Returns the SRK', () => {
        expect(config.getCompatibleArnArn(WELL_FORMED_SRK_ARN)).to.equal(
          WELL_FORMED_SRK_ARN
        )
      })

      it('Throws for a non compatible value', () => {
        expect(() => config.getCompatibleArnArn(WELL_FORMED_MRK_ARN)).to.throw()
      })
    })
  })

  describe('Given a well formed MRK arn', () => {
    const config = supplySrkKmsConfig({ mrkIdentifier: WELL_FORMED_MRK_ARN })

    it('Test getRegion', () => {
      expect((config as RegionalKmsConfig).getRegion()).equals('us-west-2')
    })

    describe('Test isCompatibleWithArn', () => {
      it('Given an equal arn', () => {
        expect(config.isCompatibleWithArn(WELL_FORMED_MRK_ARN)).equals(true)
      })

      it('Given a non-equal arn', () => {
        expect(config.isCompatibleWithArn(WELL_FORMED_MRK_ALIAS_ARN)).equals(
          false
        )
      })

      it('Given an equal mkr arn', () => {
        expect(
          supplySrkKmsConfig({
            mrkIdentifier: WELL_FORMED_MRK_ARN,
          }).isCompatibleWithArn(WELL_FORMED_MRK_ARN)
        ).equals(true)
      })

      it('Given an equal mkr arn in a different region', () => {
        expect(
          supplySrkKmsConfig({
            mrkIdentifier: WELL_FORMED_MRK_ARN,
          }).isCompatibleWithArn(WELL_FORMED_MRK_ARN_DIFFERENT_REGION)
        ).equals(true)
      })
    })

    describe('Test getCompatibleArnArn', () => {
      it('Returns the MRK', () => {
        expect(config.getCompatibleArnArn(WELL_FORMED_MRK_ARN)).to.equal(
          WELL_FORMED_MRK_ARN
        )
      })

      it('Returns the configured MRK because it is the right region', () => {
        expect(
          config.getCompatibleArnArn(WELL_FORMED_MRK_ARN_DIFFERENT_REGION)
        ).to.equal(WELL_FORMED_MRK_ARN)
      })

      it('Throws for a non compatible value', () => {
        expect(() => config.getCompatibleArnArn(WELL_FORMED_SRK_ARN)).to.throw()
      })
    })
  })

  describe('Given discovery configurations', () => {
    it('Discovery is compatible with ARNs', () => {
      const config = supplySrkKmsConfig('discovery')
      expect(config.isCompatibleWithArn(WELL_FORMED_SRK_ARN)).to.equal(true)
      expect(config.isCompatibleWithArn(WELL_FORMED_MRK_ARN)).to.equal(true)
    })

    it('MRDiscovery is compatible with ARNs', () => {
      const config = supplySrkKmsConfig({ region: 'us-west-2' })
      expect(config.isCompatibleWithArn(WELL_FORMED_SRK_ARN)).to.equal(true)
      expect(config.isCompatibleWithArn(WELL_FORMED_MRK_ARN)).to.equal(true)
    })

    it('Discovery MUST be an ARN', () => {
      const config = supplySrkKmsConfig('discovery')
      expect(() => config.isCompatibleWithArn(MALFORMED_ARN)).to.throw()
      expect(() =>
        config.isCompatibleWithArn(WELL_FORMED_SRK_ALIAS_ARN)
      ).to.throw()
      expect(() =>
        config.isCompatibleWithArn(WELL_FORMED_MRK_ALIAS_ARN)
      ).to.throw()
    })

    it('MRDiscovery MUST be an ARN', () => {
      const config = supplySrkKmsConfig({ region: 'us-west-2' })
      expect(() => config.isCompatibleWithArn(MALFORMED_ARN)).to.throw()
      expect(() =>
        config.isCompatibleWithArn(WELL_FORMED_SRK_ALIAS_ARN)
      ).to.throw()
      expect(() =>
        config.isCompatibleWithArn(WELL_FORMED_MRK_ALIAS_ARN)
      ).to.throw()
    })

    describe('Test getCompatibleArnArn for discovery', () => {
      const config = supplySrkKmsConfig('discovery')

      it('Returns the SRK', () => {
        expect(config.getCompatibleArnArn(WELL_FORMED_SRK_ARN)).to.equal(
          WELL_FORMED_SRK_ARN
        )
      })

      it('Returns the MRK', () => {
        expect(config.getCompatibleArnArn(WELL_FORMED_MRK_ARN)).to.equal(
          WELL_FORMED_MRK_ARN
        )
      })

      it('Returns the configured MRK because it is the right region', () => {
        expect(
          config.getCompatibleArnArn(WELL_FORMED_MRK_ARN_DIFFERENT_REGION)
        ).to.equal(WELL_FORMED_MRK_ARN_DIFFERENT_REGION)
      })

      it('Throws for a non compatible value', () => {
        expect(() => config.getCompatibleArnArn(ONE_PART_ARN)).to.throw()
      })
    })

    describe('Test getCompatibleArnArn for MRDiscovery', () => {
      const config = supplySrkKmsConfig({ region: 'us-east-1' })

      it('Returns the SRK', () => {
        expect(config.getCompatibleArnArn(WELL_FORMED_SRK_ARN)).to.equal(
          WELL_FORMED_SRK_ARN
        )
      })

      it('Returns the MRK', () => {
        expect(config.getCompatibleArnArn(WELL_FORMED_MRK_ARN)).to.equal(
          WELL_FORMED_MRK_ARN_DIFFERENT_REGION
        )
      })

      it('Returns the configured MRK because it is the right region', () => {
        expect(
          config.getCompatibleArnArn(WELL_FORMED_MRK_ARN_DIFFERENT_REGION)
        ).to.equal(WELL_FORMED_MRK_ARN_DIFFERENT_REGION)
      })

      it('Throws for a non compatible value', () => {
        expect(() => config.getCompatibleArnArn(ONE_PART_ARN)).to.throw()
      })
    })
  })

  //= aws-encryption-sdk-specification/framework/branch-key-store.md#aws-kms-configuration
  //= type=test
  //# This ARN MUST NOT be an Alias.
  //# This ARN MUST be a valid
  //# [AWS KMS Key ARN](./aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn).
  it('Given arns that are not parseable AWS KMS arns', () => {
    expect(() => supplySrkKmsConfig({ identifier: MALFORMED_ARN })).to.throw(
      'Malformed arn.'
    )
    expect(() => supplySrkKmsConfig({ identifier: ONE_PART_ARN })).to.throw(
      `${ONE_PART_ARN} must be a well-formed AWS KMS non-alias resource arn`
    )
  })

  it('Given a well formed SRK alias arn', () => {
    expect(() =>
      supplySrkKmsConfig({ identifier: WELL_FORMED_SRK_ALIAS_ARN })
    ).to.throw(
      `${WELL_FORMED_SRK_ALIAS_ARN} must be a well-formed AWS KMS non-alias resource arn`
    )
  })

  it('Given a well formed MRK alias arn', () => {
    expect(() =>
      supplySrkKmsConfig({ identifier: WELL_FORMED_MRK_ALIAS_ARN })
    ).to.throw(
      `${WELL_FORMED_MRK_ALIAS_ARN} must be a well-formed AWS KMS non-alias resource arn`
    )
  })
})
