
import { expect } from 'chai'
import 'mocha'
import {AlgorithmSuiteIdentifier} from '../src/algorithm_suites'
import {NodeAlgorithmSuite} from '../src/node_algorithms'

describe('NodeAlgorithmSuite', () => {
  it('should return WebCryptoAlgorithmSuite', () => {
    const test = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(test).to.be.instanceof(NodeAlgorithmSuite)
    expect(Object.isFrozen(test)).to.equal(true)
  })

  it('should throw for an id that does not exist', () => {
    expect(() =>  new NodeAlgorithmSuite(1111)).to.throw()
  })

  // Typescript is 'use strict' so these should throw
  // however if someone is not running 'use strict'
  // These changes will not take effect _if_ they throw here

  it('instance should be immutable', () => {
    const test: any = new NodeAlgorithmSuite(AlgorithmSuiteIdentifier.ALG_AES128_GCM_IV12_TAG16)
    expect(() => test.id = 0).to.throw()
    expect(() => test.name = 0).to.throw()
    expect(() => test.encryption = 0).to.throw()
    expect(() => test.keyLength = 0).to.throw()
    expect(() => test.ivLength = 0).to.throw()
    expect(() => test.tagLength = 0).to.throw()
    expect(() => test.cacheSafe = 0).to.throw()
    expect(() => test.kdf = 0).to.throw()
    expect(() => test.kdfHash = 0).to.throw()
    expect(() => test.signatureCurve = 0).to.throw()
    expect(() => test.signatureHash = 0).to.throw()

    // Make sure new properties can not be added
    // @ts-ignore
    expect(() => test.anything = 0).to.throw(/object is not extensible/)
  })

  it('prototype should be immutable', () => {
    expect(() => (<any>NodeAlgorithmSuite).prototype.id = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.name = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.encryption = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.keyLength = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.ivLength = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.tagLength = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.cacheSafe = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.kdf = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.kdfHash = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.signatureCurve = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.signatureHash = 0).to.throw()
    expect(() => (<any>NodeAlgorithmSuite).prototype.anything = 0).to.throw()
  })
})
