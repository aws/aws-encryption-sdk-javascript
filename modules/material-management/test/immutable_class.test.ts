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

/* eslint-env mocha */

import { expect } from 'chai'
import 'mocha'
import { immutableClass, immutableBaseClass, frozenClass } from '../src/immutable_class'

describe('frozenClass', () => {
  class Test {
    public name: string
    constructor (name: string) {
      this.name = name
      // This is important, or the new instance
      // can be modified
      Object.freeze(this)
    }
    qwer () {
      return 'qwer'
    }
    static asdf () {
      return 'asdf'
    }
  }
  frozenClass(Test)

  it('new Test functions as expected', () => {
    const test: any = new Test('test')
    expect(test.name).to.equal('test')
    expect(test.qwer()).to.equal('qwer')
    expect(Test.asdf()).to.equal('asdf')
  })

  it('should be instance of Test', () => {
    const test = new Test('test')
    expect(test).to.be.instanceOf(Test)
  })

  it('can not change static properties', () => {
    expect(() => { (<any>Test).asdf = 'something' }).to.throw()
  })

  it('can not add new static properties', () => {
    expect(() => { (<any>Test).something = 'something' }).to.throw()
  })

  it('can not change prototype properties', () => {
    expect(() => { (<any>Test).prototype.qwer = 'something' }).to.throw()
  })

  it('can not add new prototype properties', () => {
    expect(() => { (<any>Test).prototype.something = 'something' }).to.throw()
  })
})

describe('immutableBaseClass', () => {
  class Test {
    public name: string
    constructor (name: string) {
      this.name = name
    }
    qwer () {
      return 'qwer'
    }
    static asdf () {
      return 'asdf'
    }
  }
  immutableBaseClass(Test)

  it('new Test functions as expected', () => {
    const test: any = new Test('test')
    expect(test.name).to.equal('test')
    expect(test.qwer()).to.equal('qwer')
    expect(Test.asdf()).to.equal('asdf')
  })

  it('should be instance of Test', () => {
    const test = new Test('test')
    expect(test).to.be.instanceOf(Test)
  })

  it('is an orphaned object (not an connected to Object)', () => {
    const test = new Test('test')
    expect(Object.prototype.isPrototypeOf(test)).to.equal(false)
  })

  it('can not change static properties', () => {
    expect(() => { (<any>Test).asdf = 'something' }).to.throw()
  })

  it('can not add new static properties', () => {
    expect(() => { (<any>Test).something = 'something' }).to.throw()
  })

  it('can not change prototype properties', () => {
    expect(() => { (<any>Test).prototype.qwer = 'something' }).to.throw()
  })

  it('can not add new prototype properties', () => {
    expect(() => { (<any>Test).prototype.something = 'something' }).to.throw()
  })

  it('can not change the prototype of Test', () => {
    class Sneaky {}
    expect(() => Object.setPrototypeOf(Test.prototype, Sneaky.prototype)).to.throw()
  })
})

describe('immutableClass: Extending a BaseClass', () => {
  class Base {
    public name: string
    constructor (name: string) {
      this.name = name
    }
    qwer () {
      return 'qwer'
    }
    static asdf () {
      return 'asdf'
    }
  }
  immutableBaseClass(Base)
  class Test extends Base {
    public thing: string
    constructor (thing: string) {
      super('extend')
      this.thing = thing
      Object.freeze(this)
    }
    more () {
      return 'more'
    }
    static myCount () {
      return 1
    }
  }
  immutableClass(Test)

  it('new Test functions as expected', () => {
    const test: any = new Test('test')
    expect(test.name).to.equal('extend')
    expect(test.thing).to.equal('test')
    expect(test.more()).to.equal('more')
    expect(Test.myCount()).to.equal(1)
    expect(test.qwer()).to.equal('qwer')
    expect(Test.asdf()).to.equal('asdf')
  })

  it('should be instance of Test', () => {
    expect(new Test('test')).to.be.instanceOf(Test)
  })
  it('should be instance of Base', () => {
    expect(new Test('test')).to.be.instanceOf(Base)
  })

  // Can not change properties on Test inherited from Base
  // Properties of test are covered by tests of immutableBaseClass
  // which calls immutableClass
  it('can not change static properties', () => {
    expect(() => { (<any>Test).asdf = 'something' }).to.throw()
  })
  it('can not add new static properties', () => {
    expect(() => { (<any>Test).something = 'something' }).to.throw()
  })
  it('can not change prototype properties', () => {
    expect(() => { (<any>Test).prototype.qwer = 'something' }).to.throw()
  })
  it('can not add new prototype properties', () => {
    expect(() => { (<any>Test).prototype.something = 'something' }).to.throw()
  })
})
