// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The AWS Encryption SDK - JS does not implement
// any of the legacy Master Key Provider interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.5
//= type=exception
//# MUST implement the Master Key Provider Interface (../master-key-
//# provider-interface.md#interface)

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# On initialization the caller MUST provide:

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# The key id list MUST NOT be empty or null in strict mode.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# The key id
//# list MUST NOT contain any null or empty string values.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# All AWS KMS
//# key identifiers are be passed to Assert AWS KMS MRK are unique (aws-
//# kms-mrk-are-unique.md#Implementation) and the function MUST return
//# success.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# A
//# discovery filter MUST NOT be configured in strict mode.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# A default
//# MRK Region MUST NOT be configured in strict mode.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# In discovery mode
//# if a default MRK Region is not configured the AWS SDK Default Region
//# MUST be used.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# If an AWS SDK Default Region can not be obtained
//# initialization MUST fail.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# The key id list MUST be empty in discovery mode.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.6
//= type=exception
//# The regional client
//# supplier MUST be defined in discovery mode.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# The input MUST be the same as the Master Key Provider Get Master Key
//# (../master-key-provider-interface.md#get-master-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# The function MUST only provide master keys if the input provider id
//# equals "aws-kms".

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# In strict mode, the requested AWS KMS key ARN MUST
//# match a member of the configured key ids by using AWS KMS MRK Match
//# for Decrypt (aws-kms-mrk-match-for-decrypt.md#implementation)
//# otherwise this function MUST error.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# In discovery mode, the requested
//# AWS KMS key identifier MUST be a well formed AWS KMS ARN.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# In discovery mode, the requested
//# AWS KMS key identifier MUST be a well formed AWS KMS ARN.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# In
//# discovery mode if a discovery filter is configured the requested AWS
//# KMS key ARN's "partition" MUST match the discovery filter's
//# "partition" and the AWS KMS key ARN's "account" MUST exist in the
//# discovery filter's account id set.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# If the requested AWS KMS key identifier is not a well formed ARN
//# the AWS Region MUST be the configured default region this SHOULD be
//# obtained from the AWS SDK.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# Otherwise if the requested AWS KMS key
//# identifier is identified as a multi-Region key (aws-kms-key-
//# arn.md#identifying-an-aws-kms-multi-region-key), then AWS Region MUST
//# be the region from the AWS KMS key ARN stored in the provider info
//# from the encrypted data key.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# Otherwise if the mode is discovery then
//# the AWS Region MUST be the discovery MRK region.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# Finally if the
//# provider info is identified as a multi-Region key (aws-kms-key-
//# arn.md#identifying-an-aws-kms-multi-region-key) the AWS Region MUST
//# be the region from the AWS KMS key in the configured key ids matched
//# to the requested AWS KMS key by using AWS KMS MRK Match for Decrypt
//# (aws-kms-mrk-match-for-decrypt.md#implementation).

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# An AWS KMS client
//# MUST be obtained by calling the regional client supplier with this
//# AWS Region.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# In strict mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
//# master-key.md) MUST be returned configured with

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# In discovery mode a AWS KMS MRK Aware Master Key (aws-kms-mrk-aware-
//# master-key.md) MUST be returned configured with

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.7
//= type=exception
//# The output MUST be the same as the Master Key Provider Get Master Key
//# (../master-key-provider-interface.md#get-master-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
//= type=exception
//# The input MUST be the same as the Master Key Provider Get Master Keys
//# For Encryption (../master-key-provider-interface.md#get-master-keys-
//# for-encryption) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
//= type=exception
//# If the configured mode is discovery the function MUST return an empty
//# list.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
//= type=exception
//# If the configured mode is strict this function MUST return a
//# list of master keys obtained by calling Get Master Key (aws-kms-mrk-
//# aware-master-key-provider.md#get-master-key) for each AWS KMS key
//# identifier in the configured key ids

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.8
//= type=exception
//# The output MUST be the same as the Master Key Provider Get Master
//# Keys For Encryption (../master-key-provider-interface.md#get-master-
//# keys-for-encryption) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# The input MUST be the same as the Master Key Provider Decrypt Data
//# Key (../master-key-provider-interface.md#decrypt-data-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# The set of encrypted data keys MUST first be filtered to match this
//# master key's configuration.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# To match the encrypted data key's
//# provider ID MUST exactly match the value "aws-kms".

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# Additionally
//# each provider info MUST be a valid AWS KMS ARN (aws-kms-key-arn.md#a-
//# valid-aws-kms-arn) with a resource type of "key".

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# For each encrypted data key in the filtered set, one at a time, the
//# master key provider MUST call Get Master Key (aws-kms-mrk-aware-
//# master-key-provider.md#get-master-key) with the encrypted data key's
//# provider info as the AWS KMS key ARN.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# It MUST call Decrypt Data Key
//# (aws-kms-mrk-aware-master-key.md#decrypt-data-key) on this master key
//# with the input algorithm, this single encrypted data key, and the
//# input encryption context.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# If this attempt results in an error, then
//# these errors MUST be collected.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# If the decrypt data key call is
//# successful, then this function MUST return this result and not
//# attempt to decrypt any more encrypted data keys.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# If all the input encrypted data keys have been processed then this
//# function MUST yield an error that includes all the collected errors.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# The output MUST be the same as the Master Key Provider Decrypt Data
//# Key (../master-key-provider-interface.md#decrypt-data-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key-provider.txt#2.9
//= type=exception
//# The output MUST be the same as the Master Key Provider Decrypt Data
//# Key (../master-key-provider-interface.md#decrypt-data-key) interface.

// There appears to be something about the end of the file?
