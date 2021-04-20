// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The AWS Encryption SDK - JS does not implement
// any of the legacy Master Key interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.5
//= type=exception
//# MUST implement the Master Key Interface (../master-key-
//# interface.md#interface)

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
//= type=exception
//# On initialization, the caller MUST provide:

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
//= type=exception
//# The AWS KMS key identifier MUST NOT be null or empty.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
//= type=exception
//# The AWS KMS
//# key identifier MUST be a valid identifier (aws-kms-key-arn.md#a-
//# valid-aws-kms-identifier).

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
//= type=exception
//# The AWS KMS
//# SDK client MUST not be null.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
//= type=exception
//# The master key MUST be able to be
//# configured with an optional list of Grant Tokens.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.6
//= type=exception
//# This configuration
//# SHOULD be on initialization and SHOULD be immutable.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.7
//= type=exception
//# MUST be unchanged from the Master Key interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.8
//= type=exception
//# MUST be unchanged from the Master Key interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# The inputs MUST be the same as the Master Key Decrypt Data Key
//# (../master-key-interface.md#decrypt-data-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# The set of encrypted data keys MUST first be filtered to match this
//# master key's configuration.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# To match the encrypted data key's
//# provider ID MUST exactly match the value "aws-kms" and the the
//# function AWS KMS MRK Match for Decrypt (aws-kms-mrk-match-for-
//# decrypt.md#implementation) called with the configured AWS KMS key
//# identifier and the encrypted data key's provider info MUST return
//# "true".

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# Additionally each provider info MUST be a valid AWS KMS ARN
//# (aws-kms-key-arn.md#a-valid-aws-kms-arn) with a resource type of
//# "key".

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# For each encrypted data key in the filtered set, one at a time, the
//# master key MUST attempt to decrypt the data key.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# If this attempt
//# results in an error, then these errors MUST be collected.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# To decrypt the encrypted data key this master key MUST use the
//# configured AWS KMS client to make an AWS KMS Decrypt
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_Decrypt.html) request constructed as follows:

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# If the call succeeds then the response's "KeyId" MUST be equal to the
//# configured AWS KMS key identifier otherwise the function MUST collect
//# an error.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# The response's "Plaintext"'s length MUST equal the length
//# required by the requested algorithm suite otherwise the function MUST
//# collect an error.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# If the AWS KMS response satisfies the requirements then it MUST be
//# use and this function MUST return and not attempt to decrypt any more
//# encrypted data keys.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# If all the input encrypted data keys have been processed then this
//# function MUST yield an error that includes all the collected errors.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.9
//= type=exception
//# The output MUST be the same as the Master Key Decrypt Data Key
//# (../master-key-interface.md#decrypt-data-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
//= type=exception
//# The inputs MUST be the same as the Master Key Generate Data Key
//# (../master-key-interface.md#generate-data-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
//= type=exception
//# This
//# master key MUST use the configured AWS KMS client to make an AWS KMS
//# GenerateDatakey (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_GenerateDataKey.html) request constructed as follows:

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
//= type=exception
//# If the call succeeds the AWS KMS Generate Data Key response's
//# "Plaintext" MUST match the key derivation input length specified by
//# the algorithm suite included in the input.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
//= type=exception
//# The response's "KeyId" MUST be valid.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
//= type=exception
//# The response's "Plaintext" MUST be the plaintext in the output.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
//= type=exception
//# The
//# response's cipher text blob MUST be used as the returned as the
//# ciphertext for the encrypted data key in the output.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.10
//= type=exception
//# The output MUST be the same as the Master Key Generate Data Key
//# (../master-key-interface.md#generate-data-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
//= type=exception
//# The inputs MUST be the same as the Master Key Encrypt Data Key
//# (../master-key-interface.md#encrypt-data-key) interface.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
//= type=exception
//# The master
//# key MUST use the configured AWS KMS client to make an AWS KMS Encrypt
//# (https://docs.aws.amazon.com/kms/latest/APIReference/
//# API_Encrypt.html) request constructed as follows:

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
//= type=exception
//# The AWS KMS Encrypt response MUST contain a valid "KeyId".

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
//= type=exception
//# The
//# response's cipher text blob MUST be used as the "ciphertext" for the
//# encrypted data key.

//= compliance/framework/aws-kms/aws-kms-mrk-aware-master-key.txt#2.11
//= type=exception
//# The output MUST be the same as the Master Key Encrypt Data Key
//# (../master-key-interface.md#encrypt-data-key) interface.

// There appears to be something about the end of the file?
