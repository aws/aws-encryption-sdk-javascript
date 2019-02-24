import {AlgorithmSuiteIdentifier} from '@aws-crypto/material-management'
import {BinaryData} from './types'
import {concatBuffers} from './concat_buffers'
import {uInt16BE} from './uint_util'

export function kdfInfo(algorithmId: AlgorithmSuiteIdentifier, messageId: BinaryData) {
  return concatBuffers(
    uInt16BE(algorithmId),
    messageId
  )
}
