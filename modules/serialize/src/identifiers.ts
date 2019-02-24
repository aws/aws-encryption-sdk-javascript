
export const ENCODED_SIGNER_KEY  = 'aws-crypto-public-key'

export enum SerializationVersion {
  V1 = 1
}
Object.freeze(SerializationVersion)

export enum ContentType {
  NO_FRAMING = 1,
  FRAMED_DATA = 2
}
Object.freeze(ContentType)

export enum ContentAADString {
  FRAME_STRING_ID = 'AWSKMSEncryptionClient Frame',
  FINAL_FRAME_STRING_ID = 'AWSKMSEncryptionClient Final Frame',
  NON_FRAMED_STRING_ID = 'AWSKMSEncryptionClient Single Block',
}
Object.freeze(ContentAADString)

export enum ObjectType {
  CUSTOMER_AE_DATA = 128
}
Object.freeze(ObjectType)

export enum SequenceIdentifier {
  SEQUENCE_NUMBER_END = 0xFFFFFFFF
}
Object.freeze(SequenceIdentifier)
