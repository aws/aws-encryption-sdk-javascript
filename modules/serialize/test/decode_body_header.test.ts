// import { expect } from 'chai'
// import 'mocha'
// import {decodeFrameHeader} from '../src/decode_body_header'
// import {concatBuffers} from '../src'
// import * as fixtures from './fixtures'

// describe('decodeFrameHeader', () => {
//   it('return frame header', () => {
//     const headerInfo = {
//       messageHeader: {
//         frameLength: 99
//       },
//       algorithmSuite: {
//         ivLength: 12,
//         tagLength: 16
//       }
//     } as any

//     const test = decodeFrameHeader(fixtures.basicFrameHeader(), headerInfo, 0)
//     if (!test) throw new Error('failure')
//     expect(test.sequenceNumber).to.eql(1)
//     expect(test.iv).to.eql(fixtures.basicFrameIV())
//     expect(test.readPos).to.eql(16)
//     expect(test.tagLength).to.eql(16)
//     expect(test.isFinalFrame).to.eql(false)
//     expect(test.contentType).to.eql(2)
//   })

//   it('return final frame header', () => {
//     const headerInfo = {
//       messageHeader: {
//         frameLength: 99
//       },
//       algorithmSuite: {
//         ivLength: 12,
//         tagLength: 16
//       }
//     } as any

//     const test = decodeFrameHeader(fixtures.finalFrameHeader(), headerInfo, 0)
//     if (!test) throw new Error('failure')
//     expect(test.sequenceNumber).to.eql(1)
//     expect(test.iv).to.eql(fixtures.basicFrameIV())
//     expect(test.readPos).to.eql(24)
//     expect(test.tagLength).to.eql(16)
//     expect(test.isFinalFrame).to.eql(true)
//     expect(test.contentType).to.eql(2)
//   })

//   it('return undefined for partial basic frame', () => {
//     const frameHeader = fixtures.basicFrameHeader()
//     const headerInfo = {
//       messageHeader: {
//         frameLength: 99
//       },
//       algorithmSuite: {
//         ivLength: 12,
//         tagLength: 16
//       }
//     } as any

//     for(let i = 0; frameHeader.byteLength > i; i++) {
//       const test = decodeFrameHeader(frameHeader.slice(0, i), headerInfo, 0)
//       expect(test).to.eql(undefined)
//     }
//   })

//   it('return undefined for partial frame', () => {
//     const frameHeader = fixtures.finalFrameHeader()
//     const headerInfo = {
//       messageHeader: {
//         frameLength: 99
//       },
//       algorithmSuite: {
//         ivLength: 12,
//         tagLength: 16
//       }
//     } as any

//     for(let i = 0; frameHeader.byteLength > i; i++) {
//       const test = decodeFrameHeader(frameHeader.slice(0, i), headerInfo, 0)
//       expect(test).to.eql(undefined)
//     }
//   })

//   it('return frame header from readPos', () => {
//     const headerInfo = {
//       messageHeader: {
//         frameLength: 99
//       },
//       algorithmSuite: {
//         ivLength: 12,
//         tagLength: 16
//       }
//     } as any

//     const buffer = concatBuffers(
//       new Uint8Array(10), //pre
//       fixtures.basicFrameHeader(),
//       new Uint8Array(10) // post
//     )

//     const test = decodeFrameHeader(buffer, headerInfo, 10)
//     if (!test) throw new Error('failure')
//     expect(test.sequenceNumber).to.eql(1)
//     expect(test.iv).to.eql(fixtures.basicFrameIV())
//     expect(test.readPos).to.eql(26)
//     expect(test.tagLength).to.eql(16)
//     expect(test.isFinalFrame).to.eql(false)
//     expect(test.contentType).to.eql(2)
//   })

//   it('return final frame header from readPos', () => {
//     const headerInfo = {
//       messageHeader: {
//         frameLength: 99
//       },
//       algorithmSuite: {
//         ivLength: 12,
//         tagLength: 16
//       }
//     } as any
//     const buffer = concatBuffers(
//       new Uint8Array(10), // pre
//       fixtures.finalFrameHeader(),
//       new Uint8Array(10)  // post
//     )

//     const test = decodeFrameHeader(buffer, headerInfo, 10)
//     if (!test) throw new Error('failure')
//     expect(test.sequenceNumber).to.eql(1)
//     expect(test.iv).to.eql(fixtures.basicFrameIV())
//     expect(test.readPos).to.eql(34)
//     expect(test.tagLength).to.eql(16)
//     expect(test.isFinalFrame).to.eql(true)
//     expect(test.contentType).to.eql(2)
//   })

//   it('return undefined for partial basic frame from readPos', () => {
//     const buffer = concatBuffers(new Uint8Array(10), fixtures.basicFrameHeader())
//     const headerInfo = {
//       messageHeader: {
//         frameLength: 99
//       },
//       algorithmSuite: {
//         ivLength: 12,
//         tagLength: 16
//       }
//     } as any

//     for(let i = 10; buffer.byteLength -1 > i; i++) {
//       const test = decodeFrameHeader(buffer.slice(0, i), headerInfo, 10)
//       expect(test).to.eql(undefined)
//     }
//   })

//   it('return undefined for partial frame from readPos', () => {
//     const buffer = concatBuffers(new Uint8Array(10), fixtures.finalFrameHeader())
//     const headerInfo = {
//       messageHeader: {
//         frameLength: 99
//       },
//       algorithmSuite: {
//         ivLength: 12,
//         tagLength: 16
//       }
//     } as any

//     for(let i = 10; buffer.byteLength > i; i++) {
//       const test = decodeFrameHeader(buffer.slice(0, i), headerInfo, 10)
//       expect(test).to.eql(undefined)
//     }
//   })
// })
