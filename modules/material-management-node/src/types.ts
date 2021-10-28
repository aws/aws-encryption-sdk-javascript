import * as stream from 'stream'

// noinspection JSAnnotator
export interface AwsESDKSigner extends stream.Writable {
  update(data: Buffer): AwsESDKSigner
  sign(privateKey: string): Buffer
}

// noinspection JSAnnotator
export interface AwsESDKVerify extends stream.Writable {
  update(data: Buffer): AwsESDKVerify
  verify(publicKey: string, signature: Buffer): boolean
}
